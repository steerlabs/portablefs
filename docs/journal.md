# The Journal

The journal is PortableFS's durability layer: a fenced, ordered mutation log
in PostgreSQL. Every authority-lane write commits before its reply, and every
successful mount `fsync` drains delegated writes through the same boundary.
Authority processes are disposable caches over that truth — kill one at any
moment and a replacement replays the journal and continues exactly where
authority-durable history left off. Persistence at this layer does not depend
on checkpoints, snapshots, or authority shutdown.

## Durability contract

For live writes:

- the volume's authority orders the mutation;
- the canonical record bytes commit in one manager/runtime/writer-fenced
  PostgreSQL transaction (encoded once at staging: the identical bytes are
  the database row, the hash-chain input, the duplicate-comparison identity,
  and the retry body);
- only after commit does the authority apply and acknowledge;
- reads from connected clients observe authority-ordered state;
- history (cuts, snapshots, forks — see [history.md](./history.md)) is
  asynchronous and can never change the meaning of an acknowledged write.

Lost responses are resolved, never guessed: a commit retry sends
byte-identical record groups and the journal folds duplicates, so retries
converge on the one truth. Only a proven fence, conflict, or integrity
failure poisons a log handle.

## One authority, fenced by the database

One logical authority owns an active volume branch. The write lease lives in
the journal itself, not in any process: a claimant binds the branch's journal
generation, and every append and suspend re-proves that binding inside the
same transaction. A second claimant fences the first — there is no promotion
protocol, no split-brain window, and no warm standby. Recovery is: start a
fresh authority anywhere, claim, cold-replay (immutable base + journal
suffix), serve.

Teardown is bounded and honest. Ordinary suspend seals admission, drains
already-admitted appends through their durable acknowledgement, records an
exact receipted step-down, and exits. An UNRESOLVED suspension exits nonzero
with admission sealed and the lease unreleased, so database-time expiry
fences it; a restarted authority replays the exact receipt instead of
retrying under a new identity.

## Production honesty: attested replication

The durability promise is only as strong as the database's. In production the
authority refuses to serve until the journal database proves the configured
synchronous-replication policy (`pfj.durability_facts()` checked against
`VCS_JOURNAL_HA_POLICY_JSON`) — a policy downgrade fails closed rather than
serving with silently weakened guarantees. On a single box (the quickstart,
a home server), single-node PostgreSQL is the explicit dev posture: equal to
a local disk's durability, stated plainly rather than implied otherwise.

## The PostgreSQL security model

The journal is reachable only through narrowly scoped SECURITY DEFINER
functions, never raw tables. Migrations provision NOLOGIN roles; deployments
create login roles per environment and grant the capability role they need:

| Schema | Owner role | Caller capability | Purpose |
| --- | --- | --- | --- |
| `pfj` | `portablefs_journal_owner` | `portablefs_authority` | the live journal: claim, append, read, receipted suspend, operation state, durability evidence |
| `pfm` | `portablefs_manager_owner` | `portablefs_manager` | manager control plane: the singleton manager-epoch claim, authority runtime rows, access leases, permanent operation receipts |
| `pfh` | `portablefs_history_owner` | `portablefs_history_worker` (+ auditor) | the asynchronous history plane |

A compromised authority credential can call exactly the fenced journal API —
it cannot bypass fencing, forge chains, or read another tenant's rows. The
volume-api's admin DSN runs migrations and never ships to authority
processes; tenant tokens have no route to journal state at all. Every
function pins a safe `search_path` and fully qualifies what it touches.

`pfj3` (journal record format), `pfc2` (journaled control format: sessions,
slots, leases, locks, epochs), and `pft2` (immutable history trees) are
persisted-format identifiers — version tags on bytes, not product names.

## Bounded everything

One write ≤ 1 MiB; one intent ≤ 8 MiB; one commit group ≤ 128 records /
16 MiB; one replay page ≤ 256 records / 16 MiB; staging memory is capped.
Appends stage buffered records against reserved contiguous LSNs and become
durable-then-visible on commit — the write path never waits on object
storage, history materialization, or any global coordination.

## What this replaces

There is no per-volume WAL file as production truth, no standby pairing, no
promotion logic, no checkpoint loop in the persistence path, and no local
lifecycle ledgers: an authority holds journal truth only in the database plus
bounded process memory, and never creates `.wal`/`.meta`/`.opstate` files. A
file-backed log remains available strictly as a development and fault-test
implementation behind the same log interface.
