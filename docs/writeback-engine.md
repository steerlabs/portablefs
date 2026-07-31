# The mount write-back engine

One `writeback.Engine` per mounted `(volume, branch)` replaces the per-subtree
`session.Manager`/`Session` system. Write mode is not a mount property: every
mutation is either executed synchronously by the authority (write-through) or
acknowledged locally under an authority-issued delegation. The authority makes
the grant decision adaptively; `--fast` and `PORTABLEFS_WRITEBACK` are gone.
The only override is `PORTABLEFS_DEBUG_WRITE_THROUGH=1` (debug: never
delegate).

## Package layout

```
vcs/internal/writeback/
  engine.go      Engine: admission gates, mutation/read entry points, drain,
                 force-close, status
  wal.go         segmented mount WAL: PFW5 segment header, PFR5 frames,
                 CRC + strict torn-tail rules, rotation, the unified
                 checkpoint+reclaim operation, segment read pins
  overlay.go     sparse overlay: per-directory children sets + name deltas,
                 per-file dirty extent lists, read composition, hard bounds
  delegation.go  client delegation records, detached acquire resolution,
                 recall handling, release-first write-through, idle release
  flush.go       the one flusher: dense batches, stream digest, retry with
                 jittered backoff, watchdog goroutine, sticky degraded
  recovery.go    durable recovery jobs (job.json), discovery, the
                 attach-readiness recovery gate, rebind + replay, typed
                 conflicts
  remote.go      the context-aware authority interface (acquire/release,
                 flush, stream state, rebind/discard) clientcore adapts onto
                 fsproto
```

## Contract

- A local mutation is acknowledged only while an authority-issued delegation
  covering it is active, and only after all its WAL frames are written to the
  segment fd and the overlay delta is published. This is the normal filesystem
  `write(2)` boundary: the mutation is immediately visible to the writing
  mount, but may still be in the kernel's dirty-page cache. It becomes
  power-loss durable when the 5 ms / 4 MiB group-sync runs or an explicit
  `fsync`-class barrier forces `File.Sync`.
- One dense mutation sequence and one WAL per mount stream. A stream is
  `(mountID, walEpoch)`; its `writebackID` (`wb<mountID>x<epoch>`) keys the
  authority's durable watermark + digest, which survive session-generation
  rebinds and never reset. The client's durable watermark advances to EXACTLY
  the authority's reported `Through`, never past it; a Status-0 flush reply
  whose watermark stops short of the batch end is a protocol violation that
  parks the stream typed — records above `Through` are never dropped.
- `fsync`/`synchronize`/normal unmount are REAL barriers. `close(2)` has
  standard filesystem semantics and does not imply `fsync`:
  1. **Authority durability:** the barrier succeeds only when every covered
     mutation is durably committed AND applied at the authority. An
     unreachable, slow, or fenced authority FAILS the barrier (EIO-class);
     there is no local-only fsync outcome, ever. Before attempting the
     authority drain, the barrier synchronizes the local WAL; a failed local
     sync is itself an EIO-class barrier failure.
  2. **Frontend visibility acknowledgment:** every published invalidation
     batch carries a monotonic stream position; subscribers process batches
     strictly in order and acknowledge positions on the subscribe connection.
     The barrier completes only after every LIVE subscriber has acknowledged
     the position covering the barrier's mutations. Linux FUSE acknowledges
     after its kernel invalidation hook. On macOS 26, `portablefsd` first
     fences its user-space caches, resolves every known affected FSItem
     (including aliases discovered only through `RelatedInos`), synchronously
     pushes the authoritative size through the live regular-file vnode, and
     invalidates its cached pages with `msync(MS_INVALIDATE)`. `FlushAll`
     covers every retained regular-file FSItem. Only after that exact
     regular-file data-and-size pass succeeds does the
     daemon acknowledge the authority position. A pass that cannot establish
     a stable post-write sample within its bounded optimistic transaction
     fail-freezes the attach: frontend and control admissions return EIO, the
     position remains unacknowledged, health remains degraded for the attach
     lifetime, and an explicit unmount/restart is required. It never retries
     in a background repair worker or reports an unproven barrier.

     macOS 26 still has no stable public API for remotely revoking cached
     namespace bindings or general attributes. Known hardlink aliases and
     open identities get the exact regular-file data-and-size pass, and a
     later lookup reincarnates a remotely replaced name as a new FSItem
     without corrupting the surviving inode. Already kernel-cached remote
     namespace replacements and mode/ownership/time/link-count/directory
     attributes remain the documented FSKit 26 framework boundary. The macOS
     27 `DataCacheHandler`/cache-state API is a separate
     final-SDK release gate, not a beta-symbol fallback in this binary. A
     live-but-slow subscriber fails an authority barrier typed within a bound;
     a dropped subscriber leaves the set.
- Normal unmount cannot succeed with an unshipped acknowledged tail: the
  drain barrier runs while the mount is fully alive and a failure refuses the
  unmount (`portablefs umount` exits nonzero; the FSKit/FUSE detach keeps
  serving). Only the explicit force path (`portablefs umount --force`, which
  drives the daemon-owned `POST /v1/attaches/{ref}/unmount?force=1`
  transaction on FSKit) parks the tail as a durable recovery job — registered
  OUTSIDE the attach in the WAL store — and PRINTS the job ID.
- Recovery is an ATTACH-READINESS GATE: `writeback.Open` drains every prior
  parked stream (or parks it in an explicit terminal conflict/corrupt state)
  BEFORE the mount serves. A transient failure fails the attach; there is no
  live-serve-while-recovering and no background retry machinery.
- Peer operations overlapping an active delegation wait for recall at the
  authority and are never answered from stale state. A holder that disappears
  leaves its scopes durably `recovery-required`; peers get retryable EAGAIN
  until the stream rebinds and drains, or an operator discards it (audited,
  labeled data loss).
- Holder reads use an operation-scoped read permit. Recall immediately fences
  new mutations, but the retained overlay remains the holder's authoritative
  read view while its captured WAL tail drains. After the tail is
  authority-visible, release closes read admission, waits for every in-flight
  permit, synchronously fences frontend/user-space caches, and only then sends
  Checkin and drops the overlay. A definite Checkin or frontend-barrier
  failure reopens the retained overlay before readers wake; it never exposes a
  pre-flush authority view.
- Frontend reply admission is part of that same boundary. Under protocol minor
  3, one FSKit callback lazily receives a strictly increasing logical operation
  ID when it first issues a cache-producing RPC on its connection. Earlier
  nonpublishing RPCs carry zero; later publishing or nonpublishing RPCs from
  that callback carry the same ID and join the publication unit. The extension
  sends exactly one one-way `PublicationAck` only after the framework reply
  handler returns. Successful replies and cacheable errors such as lookup
  `ENOENT` are treated identically. A participating RPC
  that must wait for `ReleaseFor` or for a mirrored namespace lock temporarily
  suspends from the pre-handoff set, then re-enters admission before executing
  in the post-handoff view. Concurrent participants keep the unit active until
  every running sibling has either finished or suspended. This prevents the
  release from waiting on its own caller (or another caller joined to the same
  release) without allowing a pre-handoff reply to escape afterward.
  A disconnect safely retires operations whose reply was never exposed and
  operations already acknowledged. If an acknowledgement-required result was
  exposed to the frontend but the connection disappears before its
  `PublicationAck`, the attach fails coherence closed: the daemon cannot prove
  whether FSKit published that result, so admission and handoff abort instead
  of allowing stale state to cross the ownership boundary. The terminal
  handoff-gate verdict is installed before connection handlers are joined;
  the full degraded-state fence follows after they exit. This ordering wakes a
  handler blocked behind the handoff whose publication it owns, and rejects a
  replacement connection throughout that fence transition. Request IDs and
  newly allocated operation IDs are nonzero and strictly increasing, and
  early, unknown, or duplicate acknowledgements close the connection.
- Delegation grant and handoff each install a prefix cache fence. Authority
  reads carry an operation-start token, so a reply that began before the
  ownership boundary may finish its already-linearized syscall but cannot
  repopulate metadata, directory, or disk caches afterward. Per-path version
  floors remain retained across the fence, preventing delayed equal/older
  invalidations from making pre-boundary cache keys reachable again.
- Recovery conflicts (scope discarded, authority moved on) surface as typed
  job states; nothing is silently merged or discarded.
- WAL creation, recovery-registry persistence, append, rotation, checkpoint,
  group-sync, and explicit-sync failures latch one terminal mount verdict.
  Every later mutation fails EIO-class until remount, including mutations
  that would normally use the authority lane. A failure is never
  reinterpreted as delegation denial and never changes the operation's lane.
  The verdict is exposed through attach health and write-back status.
- Only a definite authority policy response (`Granted=false`) selects the
  shared authority lane after an acquire attempt. Acquire transport errors
  fail that operation visibly and are not cached as denials. A later
  application operation may make a fresh exact attempt; there is no
  background mode switch or in-process clearing of a terminal engine verdict.
- No mutation ever runs write-through INSIDE a held delegation. The one
  escape from delegated mode is drain + durable RELEASE: undecidable creates,
  unknown removes, cross-scope renames, orphan transitions, hard links, and
  xattr mutations on objects without a complete local xattr view release the
  covering delegation first, then execute on the shared lane
  (`Engine.ReleaseFor`). Xattrs on locally-born objects remain in the
  delegated WAL when the authority advertised `FeatureDelegatedXattrs`;
  v8 authorities without the delegated-xattr feature select the shared xattr
  lane from the version probe, before any mutation is attempted. One
  cancellable overlap coordinator closes the decision-to-RPC race without
  mount-wide head-of-line blocking: path-bearing authority mutations claim
  their affected subtrees and known authority inode identities through the
  RPC, while a delegation resolver claims only its scope from remote acquire
  through local grant installation. Reply-discovered hardlink identities are
  promoted atomically before installation; a hidden alias collision releases
  the new grant without exposing it. Directory mutations release equal,
  ancestor, and descendant grants before reaching the authority. The mutation
  therefore either precedes the new snapshot or releases it before reaching
  the authority, while unrelated directories remain concurrent. Server-side, a
  same-session write-through mutation still does not bypass the peer gate — it
  recalls the holder's own grant — preserving exactness as an independent
  protocol invariant.
- Published frontend identities and open handles use a two-phase release
  handoff. After the captured WAL tail is authority-visible, the mount first
  closes frontend reply admission, closes overlay read admission and waits for
  existing read permits, then fences all user-space/frontend caches. Only
  after those fallible publication steps succeed does it install the
  subtree-scoped open barrier: existing closes remain live, while new opens
  and namespace rebindings in that subtree wait. It sends batches of at most
  127 canonical open paths to
  `OpDelegationPrepareRelease`. While the exact
  `(scope, checkout epoch)` grant is still held, the authority resolves the
  batch under one reservation and durably adds any missing session open pins
  in one PFJ3 row. The aligned inode vector is adopted locally with the exact
  live-handle refcounts. The daemon then prepares every remaining active
  authority-routed Item published under that scope, including delegated
  creates whose handles have already closed, journals each assigned
  Item-to-authority identity, and holds those temporary pins through Checkin.
- Delegation prepare consumes no exact-session slot and never releases
  ownership. It is idempotent under the still-live grant: a lost reply can
  re-resolve the same barrier-frozen path bindings, and an already-held pin is
  a no-op. Recovery performs the same published-identity preparation before
  it can certify a recovered scope as locally released. After every prepared
  identity is installed, the replay-exact
  client writes an `APPLIED` watermark/digest certificate immediately followed
  by `RELEASE` in one WAL append and one sync only after frontend/read/cache
  handoff and open-pin preparation have succeeded, then sends `Checkin`. That
  ordering is the crash contract, not an optimistic acknowledgement: the scope
  is already fully drained and barred, so recovery may safely sweep a grant
  when Checkin was never committed. If Checkin committed, its reply was lost,
  and session terminalization already removed the authority stream ledger, the
  local certificate still proves the exact drained prefix and recovery needs
  no rebind. The barrier remains installed through the authority decision, then
  wakes queued opens into shared mode. Failures leave the in-process grant held
  and draining; idle cleanup never reopens delegated admission after this
  locally-final boundary.

  Attach-time recovery uses the same boundary after replaying a parked tail:
  one APPLIED certificate followed by RELEASE for every rebound scope is
  appended and synced before the first Checkin. A crash between mixed-scope
  Checkins therefore resumes from an empty local live-scope projection and
  sweeps only the authority grants that remain; it never rebinds a scope whose
  Checkin already committed.

## Client WAL

`<state>/wal/<storageID>/` holds `job.json` plus `wb-<ordinal>.pfw` segments
per stream directory (`stream-<epoch>/`). Segment header: 4 KiB, magic
`PFW5`, mountID, volume, branch, walEpoch, ordinal, first frame, first
sequence, CRC-protected. Frames: **40-byte header** (magic `PFR5`, version,
type, dense frame number, mutation seq, payload length, payload CRC32C,
header CRC32C, reserved) + payload, 8-byte aligned. Types: MUTATION
(canonical PFR1 bytes), DELEGATION, APPLIED, CLOSE, FORCED_CLOSE, RELEASE
(type 3 is a retired hole; unknown types fail closed).

Strict scanner rules: ONLY a physically short header/payload at the end of
the LAST segment is a torn tail (truncated whole + fsynced). Bad magic,
version, frame number, length, header CRC, or payload CRC — INCLUDING a
fully-present final frame — is corruption and fails closed into a `corrupt`
recovery job. Segment chains validate ordinal, epoch, mount, volume/branch
identity, and frame/sequence continuity. Malformed control payloads
(DELEGATION/RELEASE/APPLIED/CLOSE JSON) are corruption, never silently
ignored. The persistent mount identity and recovery registry use one
file-sync → atomic-rename → directory-sync primitive. An existing malformed
mount identity fails attach and is never regenerated.

Rotation at 64 MiB. Reclamation is ONE operation (`CheckpointAndReclaim`):
append the APPLIED checkpoint (watermark + digest captured atomically), sync
it, and only then delete whole segments at or below the watermark that are
neither extent-pinned nor read-pinned. A checkpoint failure reclaims nothing
and latches the WAL's sync error so later acknowledgments fail loudly.
Composed reads pin their extent snapshot's segments for the duration of the
pread, so reclamation can never delete a segment mid-read (no retry
compensation). A group-sync goroutine calls `File.Sync` on 5 ms / 4 MiB thresholds;
fsync-class barriers force it. Successful `write(2)` does not wait for that
physical sync; successful `fsync(2)` does.

## Overlay

Mount-level, path-keyed (mutation records are path-addressed PFR1; the
exclusive scope makes path identity unambiguous while held). Directory views
hold the authoritative children set from the grant snapshot plus a name
delta: lookups, readdirs, and negative answers under a held directory are
local and create needs no probe. File views hold non-overlapping dirty
extents whose bytes live in the WAL segments (never a second heap copy).
Reads compose overlay extents over base blocks (disk cache or authority
read); writing never hydrates the base. Authority acks fold covered extents
into the base view.

Hard bounds, no spill: a mutation that would grow a directory view past
16384 children or a file's extent set past 8192 extents drains, releases the
delegation, and runs write-through; `MergeReaddir` never claims completeness
for an oversize listing. Overlay memory is bounded by construction.

## Authority side (fsproto v8 + workfs + pfc2)

- `OpDelegationAcquire`: exact-identity op whose outcome is RESOLVED — a
  sent-but-unanswered request replays the identical identity until the stored
  outcome answers (lost grant replies recover the epoch), so the authority
  can never hold a grant the engine does not know exists, and only a DEFINITE
  denial routes to write-through. The path is canonicalized ONCE at the
  coordinate boundary; policy, the durable decision, and the snapshot all see
  the canonical value. Policy: one canonical recall cooldown plus scope
  shape — only an EXISTING DIRECTORY within the 8192-child bound is
  delegable (the durable overlap decision lives in the journaled
  ManagedDelegationDecide). The fresh-grant children snapshot is taken after
  the durable grant with same-session mutations gated, making it exact; the
  reply bound is real (an oversize directory ships no snapshot).
- Peer gate: reads, write-through mutations, and lock acquires that overlap a
  foreign active delegation publish a recall and wait bounded; still-held →
  EAGAIN. Write-through MUTATIONS also gate against the caller's OWN grant.
  Recovery-required scopes → EAGAIN until rebound or discarded.
- Flush: `OpFlushBatch` ships one dense global mount-stream batch plus an
  ordered table of scope/epoch runs. Every row is checked against its matching
  live grant, then all tree changes and `FlushAdvance` watermarks commit as
  one atomic group with one chained stream digest. Interleaved scopes therefore
  batch efficiently without weakening ordering or grant fencing. Requests are
  decoded under an aggregate byte budget (oversize frames drop before allocation).
- `OpWritebackState` reads the stream watermark/digest. `OpWritebackRebind`
  atomically fences a dead holder session and rebinds its recovery scopes to
  the caller after verifying stream identity + digest. `OpWritebackDiscard`
  releases a recovery scope as an audited data-loss decision.
- The `writebackID` is a RECOVERY CAPABILITY: only the mount owning the store
  flock can compute it (128-bit random mount ID, 0600 on disk), presenting it
  is what authorizes acquire/flush/state/rebind/discard against the stream,
  and the authority never echoes a stream's true ID to a caller presenting a
  different one. Operator-facing status and force-detach output use a separate
  random `jobID`; the writeback capability remains only in the 0600 recovery
  registry and is never used as the public handle.
- pfc2: `CheckoutChange` carries WritebackID and Rebind/Discard ops; session
  terminalization flips delegation grants to recovery-required instead of
  releasing them; the flush ledger keys on writebackID and stores
  {through, digest}, surviving generation changes.

## Flusher

One goroutine plus a watchdog goroutine (so a blocked network attempt cannot
starve the health verdict). Batch on 128 records / 8 MiB / 10 ms / drain
request. Every attempt is context-bounded; retries resend identical bytes
under full-jitter backoff (50 ms → 5 s cap), no attempt limit. Progress =
authority watermark advance; 30 s without progress flips sticky DEGRADED
(definite fence/conflict flips immediately), cleared only by a full drain of
pre-failure admissions. A definite fence/conflict/corruption verdict parks
the stream terminally and seals the mount's complete mutation gate. No scope
keeps mutating through another lane. The next attach verifies and replays the
exact journal before it serves, continuing the watermark exactly where it
stopped; corruption or identity conflict remains blocked for an operator
rather than being repaired, merged, reset, or discarded.
Force-close cancels the engine's lifetime context and waits for ACTUAL
goroutine termination before closing the WAL, so a late flush can never act
on a ForceClosed store. Applied extents fold out of the overlay as the
watermark advances, so steady-state heap tracks the unshipped tail. Status
reports admitted/applied sequences, pending backlog, oldest age, the sticky
terminal failure, delegation states, and recovery jobs.
