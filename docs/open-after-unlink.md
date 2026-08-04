# Open-after-unlink / orphan handling — design + status

> **Frozen v2 document.** v3 retains the authoritative server file descriptor
> and needs no orphan table. See
> [the authoritative-XFS decision](./xfs-authority-architecture.md).

POSIX delete-on-last-close: an unlinked-but-still-open file is detached from the name tree
but kept readable/writable by its open fds until the last close. portablefs implements this
with **inode identity** (Stage 1: every inode has a stable `ino` independent of its name) and
an **orphan table** at the authority (Stage 3: `OpOrphan`/`OpReap`, lease-GC'd — P6).

The whole scheme rests on the **ino-addressed file-handle model** (NFSv4-style): every open-file
operation addresses its target by stable `ino`, never by path, so no concurrent name operation on
any mount can ever steer an open handle to the wrong inode. See *Ino-addressed file handles* below.

## What is covered (implemented + validated end-to-end)

| Scenario | Mechanism | Test |
|---|---|---|
| Single-mount open-after-unlink (write-through) | mount parks on unlink if locally open; fd I/O addressed by ino | `OPEN_UNLINK_OK` |
| Single-mount open-after-unlink (write-back) | `Session.Materialize` (flush) → `Orphan` → `Forget` → mark | `WB_OPEN_UNLINK_OK` |
| rename-over-an-open-file (write-through) | `OpRename` `OrphanTarget`: park replaced dest by ino | `RENAME_OVER_OPEN_OK` |
| rename-over-an-open-dest (write-back) | flush → `RenameWithOrphanTarget` → forget → mark, under `dn.mu` | `WB_RENAME_OVER_OPEN_OK` |
| Cross-mount **multi-holder** redirect | `Orphaned`/`OrphanIno` invalidation → peer `markOrphan` | `B3_XMOUNT_REDIRECT_OK` |
| Cross-mount redirect when the invalidation is **lost** (overflow/reconnect) | peer re-derives from its stable ino: ENOENT → `GetattrOrphan(ino)` → redirect | `F1_REDERIVE_OK` |
| Concurrent unlink-vs-write resurrection (write-through) | authority `OpWrite` is **non-creating** (`WriteAtExistingAs`) | `F2_WT_RACE_CLEAN_OK` |
| Concurrent unlink-vs-write phantom (write-back) | route-lock: re-check `orphanIno` under `n.mu` before `s.Write`; seal backstop | `B4_RACE_HARD_CLEAN_OK` |
| Last-holder GC | lease-based (P6): authority sweeper reaps after the shared lease expires | unit + e2e |
| **Pure cross-mount** unlink of a peer-only-open file | **Stage 2 authority open-state**: mount eager-registers an inode open (MarkOpen, lease-renewed); authority `RemoveAs` parks instead of removing any inode a mount holds open | `STAGE2_PURE_XMOUNT_OK`, `TestRemoveOfPeerOpenFileParks…` |
| Peer unlink+**recreate-same-name** racing an in-flight handle write | **ino-addressed handles**: the write resolves by `HandleIno` through `byIno`, landing on the original (now parked) inode; the recreated name is a distinct inode it never touches | `WT_RECREATE_RACE_OK`, `TestReplayUsesLoggedCreateIno` |

Reap is **lease-only** on last close (never reaped by a single mount's local close), so a
cross-mount holder can never be reaped out from under its open fd.

### Stage 2 — authority open-state tracking

A mount registers every authority-backed (`authIno`) inode it holds open at the authority
BEFORE the open() returns, so the frozen invariant is: at the moment an open returns to the
application, the mount's hold is applied at the authority and a concurrent peer unlink parks
instead of destroys. How the registration travels is amortized by the client's per-inode open
registry (`clientcore/openreg.go`, against an authority advertising `FeatOpenRegistration`):

- the FIRST open of an unregistered inode round-trips (`MarkOpen`, awaited — never pipelined
  past the open return); concurrent opens of the same inode JOIN that in-flight registration
  and observe the same race outcome;
- a kernel CREATE (create+open) carries the registration ON the create RPC
  (`Request.RegisterOpen`): the authority records the hold before replying, so no separate
  `MarkOpen` round-trip exists on the create path and the race window is decided by the same
  server-side apply order as before;
- re-opens of an inode whose registration is still live are free (refcount); the LAST close
  RETAINS the registration (bounded LRU, renewed by `RenewOpenInodes`) instead of unmarking,
  so re-opening a recently-closed file is also free. Reuse is validated by authority
  generation stamp and renewal freshness (lease liveness), and given up on any signal the name
  binding changed (peer Orphaned/name-change invalidations, this mount's own remove/rename —
  which release synchronously ahead of the mutation — stream resubscribe, LRU pressure);
  released holds flush as batched `OpUnmarkOpenInodes`. Deferring an unmark never weakens the
  contract: until it applies the authority errs toward parking, and a spuriously parked inode
  is reclaimed by orphan lease GC.

The set is renewed periodically (`RenewOpenInodes`, crash-safe lease — retained registrations
ride the same renewal). The open-check lives at the **apply layer** (`applyMutationAs`): an
`OpRemove` or a rename-over whose target inode is held open by any mount is committed as a
**park (orphan)** instead of a remove, under one `fs.mu` hold (so a concurrent open/close
cannot slip between the check and the apply). This single point covers **all** unlink paths
uniformly — write-through `OpRemove`, write-back `OpRemove` flushed via a session batch, and
rename-over — and is replay-safe (the open-state is in-memory, so a recovered remove plainly
removes; the extra orphan only matters while fds are live). The parked node's Orphaned
invalidation reaches the holder(s), whose open fds redirect by ino. So `A unlinks/renames-over
a file only B holds open` becomes delete-on-last-close, not a broken fd.

### Ino-addressed file handles (NFSv4 model)

Open fds address their inode by **stable `ino`**, not by path. The authority keeps `byIno`, an index
of *every* live inode — named **and** parked-orphan — maintained at every create (`linkIno`), destroy
(`unlinkIno` on remove, reap, and the not-open arm of rename-over), and seeded from the base manifest
on load (`indexSubtree`). A handle op carries `HandleIno`; the authority resolves it through `byIno`
(`resolveForRW`) and applies the mutation to that inode, while still publishing the op's *current name*
for cache invalidation. Consequences:

- A peer that unlinks/renames/recreates the name **cannot** affect an open handle: the handle still
  lands on its original inode (now a parked orphan), and a recreate-of-the-same-name is a *distinct*
  inode the handle never sees. This subsumes orphan addressing — a parked orphan is just an inode that
  left the name tree but stays in `byIno`.
- On a `byIno` miss, `resolveForRW` returns **nil** — in live serving *and* replay, with **no name
  fallback ever**. A missing handle ino means the inode is genuinely gone (reaped, or a legacy
  pre-identity WAL whose `OpCreate` logged no ino and replay re-numbered), so the op fails closed
  (ENOENT; tolerant replay skips it). Falling back to `resolve(name)` would be actively dangerous:
  on a same-name unlink+recreate it converts the miss into a **wrong-generation durable write** —
  the exact corruption ino-addressing exists to prevent. Deterministic create-ino logging (below)
  makes correctly-logged handles hit `byIno` directly, so a fallback is never needed.

**Crash-recovery determinism.** Because handle ops resolve strictly by `ino`, replay must reproduce the
*same* ino a create was originally given. A checkpoint that compacts earlier create/remove churn drops
the allocator high-water, so a replay that re-derived ids from the reloaded state would re-number files
and misroute (or lose) every ino-addressed op logged after that checkpoint. The fix: inode-creating
records **log their assigned `ino`** (`preassignIno`, in both the single-commit and batch-commit paths)
and replay **uses the logged id** (`useOrAllocIno`, advancing the allocator past it) rather than
re-deriving. Pinned by `TestReplayUsesLoggedCreateIno` (+ `TestRenameOverDropsReplacedInoFromIndex` for
the `byIno` lifecycle).

## Open-vs-unlink registration race — closed

A cross-mount unlink that races a peer's *open* of the same name is resolved atomically at the
authority. `MarkOpenInode` checks the inode still exists (`byIno`) and records the open hold under a
single `fs.mu` — the very lock the unlink's park-check (`inodeOpenLocked`) also holds. So only two
orderings exist: the open registers BEFORE the unlink, which then **parks** the inode
(delete-on-last-close) so the fd survives; or the inode is already gone, and the open returns
**ENOENT**. For an authority-backed (`authIno`) file a broken fd — open succeeding onto a destroyed
inode — is impossible (the one exception, a force-revoked holder's session-born node, is the
documented residual below). The create-with-open path is closed the same way (a just-created name a peer unlinks inside the
registration window returns ENOENT, not a dead handle; with `FeatOpenRegistration` the
registration rides the create RPC itself, and the same two orderings apply to the fused hold).
A zero-RPC re-open served from a retained registration cannot lose the race at all: reuse
requires the hold to be live at the authority, and a live hold means any unlink ordered after
the open parks. Pinned by `TestMarkOpenLosesRaceToUnlink`
(unlink wins → `MarkOpenInode` reports gone) and `TestMarkOpenBeatsUnlinkParks` (open wins → the
remove parks instead of destroying), plus the reduced-op paths'
`TestCreateRegisterOpenHoldParksPeerUnlink` (fsproto) and
`TestRetainedReopenZeroRPCStillParksPeerUnlink` (clientcore).

The mount registers open-state only for a node that holds a **real authority inode** (`authIno`); an
uncommitted write-back file (path-hash, exclusively held, not peer-visible) skips registration, since
there is nothing at the authority to race. On a normal handoff this converges through the explicit protocol: a graceful release is
deferred while the file is open and entry-timeout is 0, so the next path lookup re-resolves the node
to its now-committed real inode and registration resumes.

**Residual (force-revoke of a fenced holder).** If a write-back holder is *force-revoked* — the
authority's fencing mechanism for a holder presumed dead/unresponsive — that graceful, deferred
release is bypassed. A still-live (zombie) holder can then keep a stale path-hash node for a
since-committed file and, if the new owner removes it, open that node without re-registering and get a
broken fd. This is out of scope by design: a force-revoked holder is fenced, so its writes are already
rejected by the generation/fencing token and the broken fd causes no durable harm. Healthy holders
(graceful handoff, and force-revoke of authority-born files, which always carry `authIno`) are fully
covered.
