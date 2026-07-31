# Liveness and coherence follow-ups (post 2026-07-30 incident)

Running ledger of the root-cause items surfaced by the incident and its
validation campaign. Updated as of the fix/root-architecture branch.

## Open

### 1. Metadata mutations can still join an unbounded delegation drain

The data plane no longer waits on the flush pipeline (see Fixed §8), but a
namespace mutation (create/mkdir/rename/remove/setattr/setxattr) whose
outcome the local overlay cannot decide still falls through into
`ReleaseFor` and joins the drain of a delegation whose flush may be behind
a slow or dead uplink. Volume is one wait per undecidable namespace op
(versus the data plane's thousands per second), so the shared frontend
gates now clear, but this is not a complete liveness proof for a fully
blackholed authority. Root direction: the same
acknowledged-locally-or-refused-definitely contract, extended to the
namespace lane's drain dependency.

### 2. Path-scoped delegations vs inode-shared FSItems (documented boundary)

A handoff for scope S that has already passed the frontend gate cannot be
re-blocked when an active operation subsequently discovers a hard-link
alias inside S. The old mount-wide operation scopes masked this without
fixing it (attribute reads are delegated per path, not per inode).
Closing it properly means extending an operation's scope post-reply
before publication — which would block on the gate while holding
frontendSerial and deadlock against namespace writers. Needs a design
that decouples alias discovery from the publication gate; do not patch.

### 3. Legacy WAL store checkpoint drops birthtime/flags

The dev/self-host legacy store's manifest checkpoint (`backend.Entry`)
carries no birthtime or flags, so a checkpoint→reload round trip loses
them there. The managed authority is unaffected (its durability is the
PFJ3 journal + PFT2 tree). Fix when the legacy store next changes shape.

### 4. Multi-group setattr is per-group exact, not request-atomic

A combined setattr (size+mode+owner+times+flags) splits into up to five
exact identities sent sequentially. Statically knowable refusals
(capability gates, shape validation) are preflighted before anything
applies, but a later group can still fail — definitely (another session
raced a remove: ENOENT/ESTALE) or indeterminately (transport) — after an
earlier group committed. The window predates the flags work (chmod+chown
have had it since exact sessions). Root direction: an authority-side
atomic setattr batch — one syscall outcome, per-group exact
sub-identities in a single journal record. Design it with the format
machinery; do not paper it with ordering.

### 5. Mount intent for a nonexistent branch cannot reconcile

Reproduced live: a mount attempt against a branch that does not exist
leaves a "starting" operation intent whose release replays the exact
access-lease create — which can only ever return branch-not-found, so
the intent is permanently stuck (umount and umount --force both loop).
Two root fixes: the server should answer lease-create for a missing
branch with a clean typed 404 (today the journal child spawns, gets
VOLUME_BRANCH_NOT_FOUND from the volume API, dies, and the manager
reports a generic internal error after a bootstrap crash-loop); and the
client's reconcile should treat a definite branch-absence as proof the
lease cannot exist, releasing the intent. Related transient: lease
creation in the first ~2 minutes after an authority singleton handoff
can fail UPSTREAM_UNREACHABLE (502) while the router warms; the intent
machinery preserves and later reconciles these correctly, but deploy
tooling should gate on a lease-create probe, not just /readyz.

### 6. Handle close drains its backlog inside the op pipeline

Reproduced live on the fixed build (deliberate saturation): the ENOSPC
admission contract held perfectly (definite refusals in ~11s, metadata
responsive throughout the flood, engine unpoisoned) — but CLOSING the
flooded handle with ~2 GB of admitted backlog drained synchronously in
the frontend op pipeline. Unrelated stats queued behind it until the
kernel timed out the volume and declared it dead; with the frontend
gone, the drain then stalled permanently (97 MB pending, no failure
recorded) because release completion awaits a frontend publication
acknowledgment that a dead frontend can never send. Recovery worked
(force-detach parked the tail as a durable job; no reboot), but three
root fixes fall out:
- close(2) must not synchronously drain admitted data — fsync is the
  durability barrier; close returns after WAL admission and the engine
  owns the drain (same contract as Open §1, handle lane);
- drain completion must not depend on a live frontend (the publication
  ack path must treat frontend death as a definite non-ack);
- the CLI umount preflight must classify an unresponsive/EIO mountpoint
  with NO kernel mount but a LIVE attach as the daemon-owned detach
  case (today only EIO-with-matching-kernel-mount proceeds; this shape
  refuses, and the only recovery is the daemon control API directly).

### 7. Transient ENODATA reading a peer's just-created file

Observed once (two-Mac stress): `read peer done marker: no message
available on STREAM` immediately after the file became visible; retry
succeeded implicitly. Not yet reproduced or root-caused; needs a repro
with daemon tracing before any code changes.

### 8. macOS FSKit platform gaps (Apple; Feedback radars to file)

Kernel-verified on macOS 26:
- Negative dentries are cached permanently: no revalidation against
  parent attributes and no invalidation API, so a pre-creation lookup
  blinds that machine to the name until a LOCAL mutation purges the
  directory's cache. Cross-machine "stat-poll until it appears" cannot
  work; enumeration always consults the filesystem and is the supported
  discovery pattern.
- No advisory-lock operations: cross-machine fcntl exclusion is
  impossible. The supported cross-machine mutual-exclusion primitive is
  O_EXCL create (authority-serialized, exactly-once).
- FSVolumeOpenModes carries no append intent and writes arrive with
  kernel-resolved offsets, so cross-machine O_APPEND interleaving is
  impossible on FSKit (FUSE mounts get true authority-assigned append
  offsets). Use per-writer files or write-tmp+rename.
- Replacing or re-registering an app that hosts an FSKit extension makes
  pkd SIGTERM the running extension instance, killing every live mount
  mid-write. Installers/updaters must drain mounts first.
These belong in user-facing consistency documentation as contracts, with
radars for the API gaps.

## Fixed on fix/root-architecture

- **parkExact claim transfer**: an exact identity that may have been sent
  now reaches a definite outcome before the exclusion it was issued under
  is released to anyone else. The park takes refcounted ownership of the
  caller's release (all three park sites); fence and client teardown are
  definite outcomes, and Close joins every replayer after fencing.
- **Recall-path lock order**: the recall/invalidation path never blocks
  on a NodeState mutex while holding attach.mu (onMarkOrphan collects
  under a.mu, marks outside it; NodeState.orphanIno is atomic so guards
  read it lock-free). Invariant documented at both a.mu sites and
  enforced by deterministic interleaving tests.
- **Operation scopes**: name-mutating operations report precise
  publication scopes covering every known hard-link alias, and binding
  changes bump a path epoch that conservatively widens still-active
  operations. Lookup and Enumerate deliberately REMAIN mount-wide: they
  publish per-inode attributes through per-path delegations, and a
  narrowed scope can race an already-passed handoff of a hard-link
  alias (see Open §2 for the inode-identity gate that would make
  narrowing sound).
- **FUSE publication suspension**: the ReplyGate suspends a request's
  admissions for the length of an authority-bound wait and re-admits
  through the same predicate reads already use; a canceled resume revokes
  the reply (EINTR) rather than publishing unaccounted bytes. The
  advisory-lock lane now genuinely suspends.
- **Data-plane backpressure**: a data mutation is acknowledged locally or
  refused with a definite ENOSPC; it never initiates or joins a
  delegation drain. Fsync of admitted data still drains (that is the
  relief path). Write-through data on a full local store is unaffected.
- **Dead-volume detach**: mount identification uses the kernel mount
  table (Darwin getfsstat / Linux mountinfo), never a stat through the
  possibly-dead filesystem, so a kernel-dead volume with a live daemon
  detaches exactly like a live one.
- **Authority persists birthtime and flags**: PFT2 inode fields 14/15
  (forward-only append, byte-identical goldens for old shapes), creation
  stamps birth from the record's ordered op time, Setattr persists the
  full flag word via wal OpChflags, FeatureFlagPersistence advertised.
  Zero still means "unknown" (old inodes), never 1970.

## Fixed on fix/root-liveness-metadata (merged as PR #28)

- Daemon unmount kernel-reentrancy self-deadlock (admission freeze no
  longer spans unmount(2); reclaim is teardown-safe).
- Mutation-side publication suspension (delegation-acquire, exact
  exclusion, transition-gate admission).
- Invalidation subscription anchor + attach lifetime context (peer
  creates visible in ~1s instead of minutes/never).
- Enumeration paging (stateless name-cursor cookies; verifier stable
  across continuations).
- Append intent carried end-to-end (authority-assigned offsets; FSKit
  kernel remains unable to express it).
- FSKit metadata contract (exact masks, canonical hard-link parents,
  logical AllocSize, honest flags, true ".." identity, tolerant
  unsupported attributes).
- Unlock ownership surrendered per path only after definite authority
  release; delegation-gate EAGAIN retried under suspension instead of
  surfacing errno 35.
