# Failure modes

Status: **v3 failure contract**

PortableFS v3 has one durable truth per volume — the XFS instance the authority
addresses — and one active authority epoch in front of it. Every failure below
is therefore answered by one of three questions: is the durable filesystem
still trustworthy, is this epoch still able to serve, and is this one mount
still a participant. The implementation never mixes those scopes, and neither
does this document.

The architectural decision is in
[xfs-authority-architecture.md](./xfs-authority-architecture.md); the
application-visible guarantees are in
[consistency-model.md](./consistency-model.md).

## Failure scopes

| scope | what it costs | recovery |
| --- | --- | --- |
| storage fatal | the epoch; the process exits | investigate the device/filesystem, then a new epoch |
| coherence poison | the epoch | a new epoch |
| participant fenced | one mount's session | that mount revokes itself and remounts |
| session fenced | one mount's session | remount |
| ordinary errno | one operation | the application's own error handling |

Responses carry the scope explicitly rather than making the client infer it
from an errno: `FAILURE_CLASS_STORAGE`, `FAILURE_CLASS_COHERENCE`,
`FAILURE_CLASS_ROUTES` and `FAILURE_CLASS_INTERNAL`. A bare `EIO` cannot say
whether the filesystem is gone or the authority merely failed to recognise one
of its own errors, and those need different operator actions.

## Storage failure fences the store and ends the epoch

`EIO` is the classic device failure, `EUCLEAN` is how XFS surfaces detected
metadata corruption, `ESHUTDOWN` is a filesystem the kernel already shut down
after an earlier failure, and `ENOTRECOVERABLE` is terminal state loss. All
four are treated identically: the store is permanently fenced for this epoch
and the authority process exits.

Fencing is not a retry backoff. After it, no mutation is attempted against a
filesystem whose durable state can no longer be trusted, because continuing to
serve would mean acknowledging writes that may never have landed. Operator
guidance: treat the exit as not-ready, investigate the device and filesystem,
and do not restart-loop a volume onto unhealthy storage.

## Authority death, restart, and epoch change

The authority holds no durable state of its own, so there is no promotion
protocol, no warm standby to keep consistent, and nothing to replay. A
replacement mounts the same XFS, increments the epoch, and serves.

Everything scoped to the old epoch is gone at that instant:

- All object and open-handle capabilities are invalid. Tokens are bound to the
  epoch by construction, so a stale one is exactly a stale handle: `ESTALE`.
- All POSIX and `flock` locks are released. They were epoch runtime state.
- All same-epoch replay slots are gone, which is why no mutation is continued
  across the boundary.
- All server file descriptors are closed. An unlinked-but-still-open file whose
  last name was already removed is destroyed by XFS at that point and cannot be
  recovered; holders receive `ESTALE`/`EIO`. See
  [open-after-unlink.md](./open-after-unlink.md).

What survives is exactly what XFS made durable, plus the durable strict-mount
membership record described below. `TestUnmountRemountObservesDurableState` in
the privileged suite pins the first half of that.

## A lost reply is UNCERTAIN, not a retry

A connection can die after XFS has already applied a mutation but before its
reply arrives. The authority does not invent an errno for that, and the client
does not replay it into a new epoch.

The response carries an explicit `uncertain` marker, and the server-side marker
`ErrOutcomeUncertain` (`vcs/internal/xfsstore`) deliberately carries no errno of
its own, so an uncertain outcome can never be mistaken for the storage `EIO`
that fences a volume. The application observes a definite error and inspects
current state to decide what happened. Append offsets and namespace outcomes
are never guessed.

Inside a live epoch the opposite holds: duplicate delivery returns the recorded
outcome from the session's replay slot and never re-executes.

## Session fencing

A mount session ends — every further operation from it fails, and the mount
must remount — for these reasons:

- **Proven client-state loss.** A replay slot identity reused with a different
  request (`ErrRequestMismatch`), or a slot sequence that gapped
  (`ErrSequenceGap`). Interleaving with lost state would be undefined, so the
  authority refuses to execute anything further from that session.
- **A slot outside the negotiated range** (`ErrSlotRange`).
- **Session lease expiry.** Keepalive is a liveness proof; a session that stops
  renewing is reaped along with its locks and handles.
- **Authorization expiry.** Keepalive cannot extend the signed authorization
  deadline. A standalone mount must use a new credential and mount again. A
  hosted live mount may extend its existing session only with the exact next
  manager-signed `Reauthorize` grant; an expired, broadened, gapped, or changed
  replay is refused and may fence the session.
- **Strict participant fencing**, below.

A fenced session never re-establishes itself under the same identity. A zombie
that minted a fresh generation could overwrite its successor's work.
`TestSessionExpiryReleasesABlockedLockWait` pins that a blocked lock waiter is
released rather than left hanging when its session ends, and
`TestAuthorityLossFailsCleanlyInsteadOfHanging` pins the same property for the
authority disappearing underneath a mount.

## A lost strict participant is fenced individually

This is the availability decision that matters most in a multi-mount volume: a
single dead cached frontend must not freeze the volume.

A broken session, a missed repair budget, or an acknowledgement-cursor
violation removes exactly that mount from admission to later visibility
barriers and ends its authority session immediately through the
`SessionFencer`. The volume keeps serving; the running mutation completes.

The obligation already held by that running mutation is retained for one full
additional declared repair-budget grace and then discharged. A failed
participant therefore costs at most two budgets — one phase deadline plus one
fencing grace — rather than an unbounded volume outage. The grace is
load-bearing only when the frontend can prove its old kernel cache became
unservable before the grace ends.

Linux proves it by detaching and aborting FUSE (below). The SDK-26 product
supervisor also identity-checks and force-unmounts its exact FSKit mount after
daemon/session failure. Live
testing with a cached held descriptor showed reads continue for 8.6 seconds,
the watchdog force-unmounts at about 10 seconds, and every later `pread` fails
`EIO`, inside the fencing grace. This is the terminal boundary of the named
macOS best-effort tier; it does not make that tier exact. See
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md).

Participant-scoped fencing is reported to the client as `ESTALE`, never as a
volume-wide I/O failure, precisely because the volume is unaffected.

## Linux self-revocation

When a strict Linux mount learns it can no longer repair, `Mount.revoke`
(`vcs/internal/fusev3/coherence_linux.go`) makes the stale cache unservable in
three steps, strongest first:

1. every new request is refused synchronously, before the call returns;
2. the mount point is detached with `MNT_DETACH`, so the tree is unreachable
   from the namespace root in one syscall, and every published kernel binding
   is withdrawn within the declared repair budget;
3. the FUSE connection is aborted through
   `/sys/fs/fuse/connections/<minor>/abort`, after which there is no request
   this frontend could answer wrongly at all.

Afterwards the mount reports `ENOTCONN`. That is the exact truth: this frontend
is no longer connected to anything it may speak for.

## Coherence poison

Poison is reserved for authority-internal invariant violations — a COMPLETE
naming a coordinate that PREPARE did not, a participant found holding two
outstanding events. Those are defects no mount can cause, and no client input
can trigger. `ErrVisibilityPoisoned` is permanent for the epoch and recovery
requires a new one.

The distinction from participant fencing is deliberate and must stay that way:
one is a peer that died, the other is a bug in the coordinator. Collapsing them
would either turn a dead laptop into a volume outage or turn a coordinator
defect into silently degraded coherence.

## Durable strict-mount membership and restart refusal

Durable membership is the one piece of authority state that outlives an epoch.
It records only which cached kernel mounts a previous epoch admitted — no
paths, inodes, bytes, mutations, or history — and it exists so a *replacement*
authority cannot start serving underneath a kernel cache that is still live on
some machine.

- It is deliberately **not** cleared by fencing. A fenced mount is gone from
  this epoch's barrier while still recorded.
- Only the official supervisor's mount-absence observation on the authenticated
  request for that exact session deactivates a record. The supervisor first
  establishes its platform's terminal mount conditions; a crash, missing
  observation, ambiguous kernel state, or delivery failure keeps the record.
- A Linux attach that fails before kernel mount creation uses its random
  per-attempt FUSE source as the identity. The session is deactivated only if
  that source is absent everywhere in `mountinfo` and no serving loop can still
  install it; path absence alone is not evidence.
- On startup, a replacement authority refuses to serve until every recorded
  prior strict kernel mount is proven absent, or the operator asserts
  `--prior-strict-mounts-fenced` once after the control plane has actually
  fenced those hosts.

Availability is preserved inside an epoch and paid for across one. Never set
`--prior-strict-mounts-fenced` merely because the authority process or its
network connection stopped; a dead socket is not proof that a kernel cache is
unservable. Deployment detail is in
[xfs-authority-deployment.md](./xfs-authority-deployment.md).

## Mount process or machine dies

A v3 mount holds no durability debt: every acknowledged write was already
applied to XFS before `write(2)` returned. A dead mount therefore loses
nothing that was acknowledged. What it loses is its session — locks, handles,
and any unlinked-but-open inode whose last name was already removed.

Surviving mounts are unaffected. The coherence matrix asserts that directly
with `peer_loss_does_not_break_surviving_mount`, which is only possible because
the mounts are separate OS processes that can be killed uncleanly.

## Capacity, quota, and admission

- **Quota and disk exhaustion surface as the kernel's own `EDQUOT` and
  `ENOSPC`.** They are ordinary operation failures. They do not fence the store
  and are not in the fatal-storage set.
- **`statfs` retains the ordinary local-XFS meaning** of cell-wide physical
  capacity. Purchased per-volume entitlement is reported by quota and billing
  APIs, not by `statfs`.
- **Deployment-sized bounds** on live sessions, replay slots, lock records,
  in-flight requests, frame allocations, descriptors, tasks, and memory are
  denial-of-service admission controls, not filesystem-size limits. Reaching one
  answers `EAGAIN`. Because launch isolates one worker per volume, exhausting
  them can fail that volume but cannot consume another tenant's worker state.

## Routing revision mismatch

`.portablefs/local-dirs` is volume-wide configuration replaced only through the
authority's admin `ApplyRoutes`, which canonicalizes the declaration and
compare-and-swaps its revision. An attach or an existing session on a different
revision fails closed.

The refusal is recoverable without spending a single-use capability: the
routing check runs *before* the capability is verified, and the refusal carries
the volume's active canonical rules, so a mount adopts them and attaches again
on the same capability. A second refusal is a real disagreement and is surfaced
verbatim; `routes_revision_mismatch` in the coherence matrix asserts that
contract including the attempt count. A routing change applied while mounts are
live revokes them with a remount message rather than letting two machines
disagree about which paths are shared. If durable commit fails after PREPARE, current production mounts have already
revoked during PREPARE and are not preserved. A truthful reported-active COMPLETE is relevant only to a future frontend that
explicitly staged and ACKed PREPARE without leaving. A definite pre-publication
failure reports the old revision and `Applied=false`; a post-rename
durability-uncertain failure reports the next revision and `Applied=true`.
Fresh attaches use whichever revision the commit reports active.

## Launch topology

Launch is one Nitro EC2 instance and one encrypted, non-Multi-Attach EBS volume
formatted XFS, with `DeleteOnTermination=false` so the volume outlives the
instance. This is single-AZ durable storage, **not** cross-AZ HA. EBS
replicates within one AZ; SLOs must use that fact rather than call one volume a
replica set.

Instance replacement is manual and ordered: prove the previous process cannot
write, detach, attach in the same AZ, mount XFS and let journal replay finish,
start a fresh epoch, publish the endpoint. There is no automatic second writer.

Heartbeats, DNS, and leases do not fence an old writer. Force-detach is an
emergency action, not a promotion protocol. Do not call EBS Multi-Attach a
replica and do not mount ordinary XFS read-write on two hosts. Optional
active-passive HA is a separate topology requiring independent fencing,
one-writer enforcement, epoch advancement, and destructive split-brain tests
before it is credible.

Backups are disaster recovery, not a failure mode of the filesystem: they
protect against deletion, bugs, compromised credentials, and operator error —
the failures a live replica would faithfully copy. A snapshot is never mounted
inside the live namespace and users see no version history. See
[xfs-authority-deployment.md](./xfs-authority-deployment.md).

## What this contract does not promise

- Transparent exactly-once mutation across authority death. An uncertain
  outcome is reported as uncertain.
- Recovery of unlinked-but-open file content across an epoch change.
- Cross-AZ high availability at launch.
- Automatic failover of any kind.
- Any production macOS frontend today. The retained qualification adapter's
  force-unmount evidence does not close its source and peer cache boundaries.

## Verification

These are the executable gates, not inspection:

```bash
bash scripts/verify-local.sh            # the single local merge gate
bash scripts/xfs-fuse-integration.sh    # privileged Linux: real XFS + kernel FUSE
bash scripts/coherence-matrix-linux.sh  # black-box two-mount matrix, with controls
```

The privileged suite enumerates every test that must actually run and pass; a
required test that is renamed, deleted, or skipped fails the job rather than
quietly shrinking coverage. The coherence matrix proves a red result is
reachable — a disjoint-namespace phase and a first-success stale-view phase —
before it reports a green one.
