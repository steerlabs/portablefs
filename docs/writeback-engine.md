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
  segment fd and the overlay delta is published.
- One dense mutation sequence and one WAL per mount stream. A stream is
  `(mountID, walEpoch)`; its `writebackID` (`wb<mountID>x<epoch>`) keys the
  authority's durable watermark + digest, which survive session-generation
  rebinds and never reset. The client's durable watermark advances to EXACTLY
  the authority's reported `Through`, never past it; a Status-0 flush reply
  whose watermark stops short of the batch end is a protocol violation that
  parks the stream typed — records above `Through` are never dropped.
- `fsync`/`close`/`synchronize`/normal unmount are REAL barriers:
  1. **Authority durability:** the barrier succeeds only when every covered
     mutation is durably committed AND applied at the authority. An
     unreachable, slow, or fenced authority FAILS the barrier (EIO-class);
     there is no local-only fsync outcome, ever. The un-flushed tail stays
     crash-safe in the local WAL and drains when the authority answers.
  2. **Frontend visibility acknowledgment:** every published invalidation batch carries
     a monotonic stream position; subscribers process batches strictly in
     order and acknowledge positions on the subscribe connection. The barrier
     completes only after every LIVE subscriber has acknowledged the position
     covering the barrier's mutations. Linux FUSE acknowledges after its
     kernel invalidation hook, so cross-machine read-after-fsync is exact for
     FUSE peers. `portablefsd` acknowledges after invalidating its user-space
     caches and delivering the event to its frontend stream. macOS 26 FSKit
     exposes no kernel-cache invalidation hook, so reads served wholly from
     that kernel cache are explicitly outside this visibility claim; the
     authority-durability barrier remains exact. A live-but-slow subscriber
     fails the barrier typed within a bound; a dropped subscriber leaves the
     set. The wait costs one RTT to the slowest live subscriber, only on
     barriers.
- Normal unmount cannot succeed with an unshipped acknowledged tail: the
  drain barrier runs while the mount is fully alive and a failure refuses the
  unmount (`portablefs umount` exits nonzero; the FSKit/FUSE detach keeps
  serving). Only the explicit force path (`portablefs umount --force`, the
  daemon's `?force=1` detach) parks the tail as a durable recovery job —
  registered OUTSIDE the attach in the WAL store — and PRINTS the job ID.
- Recovery is an ATTACH-READINESS GATE: `writeback.Open` drains every prior
  parked stream (or parks it in an explicit terminal conflict/corrupt state)
  BEFORE the mount serves. A transient failure fails the attach; there is no
  live-serve-while-recovering and no background retry machinery.
- Peer operations overlapping an active delegation wait for recall at the
  authority and are never answered from stale state. A holder that disappears
  leaves its scopes durably `recovery-required`; peers get retryable EAGAIN
  until the stream rebinds and drains, or an operator discards it (audited,
  labeled data loss).
- Recovery conflicts (scope discarded, authority moved on) surface as typed
  job states; nothing is silently merged or discarded.
- No mutation ever runs write-through INSIDE a held delegation. The one
  escape from delegated mode is drain + durable RELEASE: undecidable creates,
  unknown removes, cross-scope renames, orphan transitions, hard links, and
  xattr mutations release the covering delegation first, then execute on the
  shared lane (`Engine.ReleaseFor`). Server-side, a same-session
  write-through mutation does not bypass the peer gate — it recalls the
  holder's own grant — which is what makes the grant-time children snapshot
  exact against same-session races.
- Open handles under a releasing scope gain authority-durable open pins
  BEFORE the durable release (post-drain), so a peer unlink after the release
  parks the inode (open-after-unlink) instead of destroying it; the pin is
  owned by the handle and retires on its last close.

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
ignored.

Rotation at 64 MiB. Reclamation is ONE operation (`CheckpointAndReclaim`):
append the APPLIED checkpoint (watermark + digest captured atomically), sync
it, and only then delete whole segments at or below the watermark that are
neither extent-pinned nor read-pinned. A checkpoint failure reclaims nothing
and latches the WAL's sync error so later acknowledgments fail loudly.
Composed reads pin their extent snapshot's segments for the duration of the
pread, so reclamation can never delete a segment mid-read (no retry
compensation). A group-sync goroutine fdatasyncs on 5 ms / 4 MiB thresholds;
fsync-class barriers force it.

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

## Authority side (fsproto v6 + workfs + pfc2)

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
- Flush: `OpFlushBatch` ships dense per-scope runs of the mount stream with a
  chained stream digest; `FlushAdvance` rows commit tree state + watermark +
  digest atomically. Requests are decoded under an aggregate byte budget
  (oversize frames drop before allocation).
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
the stream terminally: mutations under its held scopes fail typed, untouched
scopes keep working write-through, and recovery happens on the NEXT attach —
before it serves — continuing the watermark exactly where it stopped.
Force-close cancels the engine's lifetime context and waits for ACTUAL
goroutine termination before closing the WAL, so a late flush can never act
on a ForceClosed store. Applied extents fold out of the overlay as the
watermark advances, so steady-state heap tracks the unshipped tail. Status
reports admitted/synced/applied sequences, pending backlog, oldest age, last
failure, delegation states, recovery jobs.
