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

### 4. Transient ENODATA reading a peer's just-created file

Observed once (two-Mac stress): `read peer done marker: no message
available on STREAM` immediately after the file became visible; retry
succeeded implicitly. Not yet reproduced or root-caused; needs a repro
with daemon tracing before any code changes.

### 5. macOS FSKit platform gaps (Apple; Feedback radars to file)

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
- **Concrete operation scopes**: lookups and enumerations report their
  real paths instead of mount-wide `""`; binding changes bump a path
  epoch that conservatively widens still-active operations. Root
  enumeration and truly detached handles remain legitimately mount-wide.
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
