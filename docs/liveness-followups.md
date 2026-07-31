# Liveness and coherence follow-ups (post 2026-07-30 incident)

Status of the remaining root-cause items identified by the post-incident
audit of merge `5d5b8a7` and the live re-wedge reproduced during solo
validation. Items fixed on `fix/root-liveness-metadata` are listed at the
end for context. Each open item below needs its own dedicated change with
tests; none is a quick patch.

## Open

### 1. Parked exact identities outlive their exclusion claim (data integrity)

`vcs/internal/fsproto/session_client.go` `parkExact` (and the two
equivalent park sites in `coordinate_client.go`) replay an
unknown-outcome exact identity in a detached goroutine until definite,
fence, or client close. The frontend caller meanwhile returns
`ErrMutationUnknown` and releases its delegation-transition claim,
`Volume.exactMu`, and `writeback.BeginExact` exclusion. A parked identity
can therefore execute minutes later, after a new delegation over the same
scope was granted to this mount or a peer. The authority's journal
reservation re-check orders the write server-side, but the client's local
overlay/registry state can diverge from what it believes it exclusively
owns.

Candidate root designs (pick one):
- **Foreground-definite**: resolve the ambiguous identity synchronously
  before the operation returns (publication stays suspended for the whole
  bracket, so this cannot stall a handoff; force-detach fences the session
  and unblocks the wait). Simplest semantics; reduces cancellation
  responsiveness during transport outages.
- **Claim transfer**: the park takes ownership of the caller's claim and
  releases it when the identity reaches a definite outcome. Preserves
  fast cancellation; requires plumbing a claim-transfer hook through
  `DoContext` into all three park sites and making the clientcore `end()`
  closures transfer-aware.

### 2. `n.mu` held across suspended waits vs the recall path (untimed cycle)

A suspended frontend mutation holds its `NodeState.mu` (e.g. `Write` at
`vcs/internal/clientcore/ops.go:932-943`) while its `resume()` can block
on any overlapping handoff. The recall path takes `attach.mu` and then
`NodeState.mu` (`onMarkOrphan`, `protectOpenPins`), and
`persistAssignedAuthorityIdentities` needs `attach.mu`. With a mount-wide
operation scope (item 3) the cycle closes with no timeout on any edge.
Root direction: either the recall path must never block on `n.mu` while
holding `a.mu`, or operations must not hold `n.mu` across suspended
authority waits. Item 3 removes the disjoint-scope trigger but the
same-scope discipline should be made an asserted invariant.

### 3. Mount-wide `""` operation scopes over-serialize handoffs

`vcs/internal/portablefsd/coherence_refresh.go`: `LookupRequest` and
`EnumerateRequest` always report `unknown()` (`[]string{""}`), and any
handle without a live alias reports mount-wide scope. `scopesOverlap`
treats `""` as overlapping everything, so these operations block every
handoff while active and their `resume()` blocks on every active handoff.
Lookup and enumerate know their concrete parent path; derive it. Detached
handles are the only legitimately mount-wide case.

### 4. FUSE frontend never arms `OnOperationWait`

`vcs/cmd/portablefs/internal/cli/fusemount.go` sets the ReplyGate handoff
hooks but not `OnOperationWait`, so the entire publication-suspension
mechanism (and with it the advisory-lock suspension) is inert on FUSE
mounts. The ReplyGate needs a suspend/resume notion for its admissions,
carried through the operation context, mirroring the FSKit frontend.

### 5. FSKit provides no advisory-lock surface (platform limitation)

macOS 26 FSKit (`FSVolume.h`) exposes no byte-range/advisory lock
operations to extensions; the kernel resolves `fcntl` locks machine-
locally. Cross-machine advisory-lock exclusion therefore cannot exist on
FSKit mounts regardless of client code. `clientcore/locks.go` is
reachable only from FUSE. Document this limitation user-facing; the
`pfs-mount-stress` `locked-counter` check will truthfully fail across two
FSKit Macs.

Related: `WaitSetLock` still re-issues fresh exact identities on EAGAIN
every `LockPollInterval`, and cannot distinguish gate-recall EAGAIN from
genuine lock contention (FUSE-only today).

### 6. Authority `AllocSize`/`Flags`/`Birthtime` deployment gap

The production authority predates the v5 attr fields, so gob decodes
them as zero. The client now derives the logical-bytes `AllocSize`
policy locally when absent; once the authority (`fsproto.attrOf`) is
deployed with the fields, add a protocol feature bit so absent-vs-zero
is explicit rather than inferred.

### 7. Observation: item-getattr ESTALE bursts during name churn

During rapid create/hardlink/rename/remove churn on a real macOS 26 host,
the unified log shows steady `getStandardItemAttributesForItem` replies of
ESTALE(70)/ENOENT(2) — the kernel refreshing attributes of items that were
just removed or whose generation was retired by reclaim. No functional
operation failed and churn completed, but the alternating ESTALE→ENOENT
pattern suggests the host retries an ESTALE item-getattr once before
accepting death. Worth confirming the intended reply for a
removed-but-still-referenced item (an orphan with live kernel references
should arguably still serve attributes rather than ESTALE).

## Fixed on fix/root-liveness-metadata

- Daemon unmount kernel-reentrancy self-deadlock: the admission freeze
  (`frontendSerial` + `nsMu`) no longer spans `unix.Unmount(2)` in
  `detachWithFinalizer` / `forceUnmountFSKit`; reclaim is admitted during
  prepared detach and idempotent after detach. Reproduced live (spindump:
  daemon in `vflush → lifs_vnop_reclaim → lifs_wait_req_completion` with
  the extension idle) before the fix; regression tests
  `TestDetachFinalizerAdmitsKernelReclaim`,
  `TestForceUnmountAdmitsKernelReclaim`,
  `TestReclaimAdmittedDuringPreparedDetach`.
- Publication suspension now covers the delegation-acquire flight wait
  (`writeback.Engine.acquire`), the exact-exclusion acquisition
  (`Engine.BeginExact`), and transition-gate admission/extend
  (`Volume.beginAuthorityMutation`) — the mutation-side reciprocal
  cross-client wait geometry.
- Unlock surrenders local lock records per path only after that path's
  authority release succeeds (`UnlockTargets`/`CommitUnlock`), and range
  splits keep their lock type.
- Definite delegation-gate EAGAIN on exact file mutations is retried
  under suspension in `DoContext` instead of surfacing errno 35 to
  applications.
