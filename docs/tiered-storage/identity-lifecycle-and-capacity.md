# Tiered storage: identity, lifecycle, and capacity contract

Status: **Phase 0 contract, revision 3 — incorporates both adversarial
reviews (review-phase0-codex.md, review-phase0-codex-r2.md); frozen before
implementation**

## 0. Trust boundary for host facts

The cell's trusted computing base is the set of root-installed components:
the helper, the authority, the archiver, and the hydrator binaries plus
their root-provisioned units and configuration. The unprivileged cell agent
is **not** in that base — it is a transport. The contract therefore never
lets an agent-forged observation cause data loss:

- Every destructive or authorization-bearing host action is executed by the
  helper, and the helper independently re-verifies its local preconditions
  before acting: it refuses an `ARCHIVE` phase without the authority's
  local quiesce proof (§2 step 1), refuses `DESTROY` without the Manager's
  seal having been planned after §2 step 3, refuses `RELEASE` without its
  own recorded destroy proof, and aborts on a plan that removes a
  non-tombstoned volume.
- The Manager commits `ARCHIVED` only after its own archive-store
  verification (§2 step 3), never on an observation alone.
- Consequence: a compromised agent can delay or wedge a cell (which it can
  already do by refusing to reconcile — a visible, alerting condition),
  but it cannot cause the Manager to believe data is sealed, destroyed, or
  released when it is not, and it cannot cause the helper to destroy data
  the Manager has not verified as sealed. No helper attestation key is
  required; this argument is the reason.

This document is the control-plane contract for the archive tier. It amends
[hosted-control-plane.md](../hosted-control-plane.md) and is grounded in the
current implementation (`vcs/internal/controlplane`, `vcs/internal/cellplan`,
`vcs/internal/cellhelper`, `vcs/internal/cellhost`). The pack/manifest format
is [pack-format.md](./pack-format.md); restore-mode serving, the archiver and
hydrator processes, and the Files-gateway changes are
[restore-mode.md](./restore-mode.md).

## 1. Identity model

```text
Product workspace
      | stable binding — never changes across archive/wake
PortableFS VolumeID                 stable for the volume's lifetime
      |
Authority epoch (durable uint64)    +1 on every authority replacement
      |
Placement (per-placement identity)  cell, placement sequence, project ID,
                                    service UID/GID, port, endpoint name —
                                    allocated fresh per placement, never reused
      |
Wire session epoch (random 16B)     per authority process, unchanged from v1
```

Four identities, each with one meaning:

- **VolumeID** — the durable identity a product stores. Archive, wake, and
  future migration never change it.
- **Authority epoch** — the v1 `AuthorityGeneration` renamed (the JSON key
  `authority_generation` is retained on every existing wire surface). It is
  the durable counter naming which authorization regime is current: grants,
  capabilities, and enrollments pin it and fail closed across an advance,
  exactly as in v1. It advances on every within-placement fencing restart
  (existing behavior) and on every archive-cycle transition (§2). It is
  **not** the wire session epoch: every authority process still mints a
  random 16-byte protocol epoch at startup
  (`volumeserver/session.go:30-34`), so an accidental same-epoch process
  restart can never resurrect a replay domain. Nothing in this plan touches
  the wire epoch.
- **Placement** — one volume's residence on one cell. Each placement gets a
  fresh identity tuple from the cell's monotonic allocators plus a
  per-volume monotonic `PlacementSequence` (starts at 1 for the v1
  placement). Within a placement, the tuple and the endpoint name are
  immutable (the helper's `immutableAssignmentMatches` rule is preserved);
  the epoch advances freely within a placement. Identity tuples are never
  reused.
- Authority endpoint names are **per-placement**, not per-epoch:
  `v-<compact-volume-id>-p<placement-sequence>.<cell-dns-zone>`. Within a
  placement the name is stable across fencing restarts (certificates,
  drop-ins, and the helper's immutability check keep working exactly as
  today); a wake creates a new placement and therefore a new name, so
  nothing that survived an archive cycle can hold a still-valid endpoint
  name. Clients always resolve endpoints through the Manager grant/exchange
  flow, which pins the epoch. `AuthorityID == AuthorityServerName` stays
  enforced. The v1 placement keeps its existing un-suffixed name
  (`v-<id>.<zone>`) for compatibility; sequence suffixes start at wake.
- The per-volume service account name is per-placement:
  `pfs-` + lowercase base32, no padding, of the first 16 bytes of
  `SHA-256(preimage)` where the preimage is exactly the 16 RFC 4122 UUID
  bytes of the volume ID followed by the placement sequence as an unsigned
  big-endian 64-bit integer (30 chars total, within systemd's 31-character
  user-name bound; a golden vector pins the encoding). A pre-existing
  account whose name matches but whose UID/GID differ is a placement
  refusal — `verifyServiceIdentity` fails closed in both directions and
  never adopts or renames. The v1 placement keeps the
  existing `pfs-<base32(volume-uuid)>` name. Accounts remain persistent and
  are never deleted — allocator identities are never reused — so a volume
  that lived on a cell N times leaves N accounts, each having owned a
  distinct UID exactly once. `verifyServiceIdentity`'s four-way check works
  unchanged because each placement's name↔UID binding is unique.

Epoch advance in the archive cycle is machine-gated by the **authority
quiesce protocol** — an attach-closed, process-bound proof, not two racy
snapshots:

1. The helper writes a root-owned quiesce-request file (containing a fresh
   random quiesce nonce) into the volume's ConfigRoot, visible to the
   authority read-only at `/run/portablefs-volume`.
2. The authority observes the request (checked at strict-attach admission
   and on a coarse poll) and enters quiesce mode: it **refuses new strict
   attaches** with a named refusal while continuing to serve existing
   sessions and accept `CleanDetach`. Quiesce mode is in-process state; a
   crashed authority is simply absent, and the helper never starts a new
   one during an `ARCHIVE` phase.
3. When the authority — which owns the membership file and its lock, and
   serializes every `Activate`/`Deactivate` — observes the active set
   empty while attach admission is closed, it writes a durable
   quiesce-proof record into StateRoot `{volume, authority epoch, wire
   session epoch, quiesce nonce, membership-empty}` and keeps refusing
   attaches. Because admission is closed before the emptiness check and
   the check is made under the same lock that admission uses, the set
   cannot become non-empty after the proof exists.
4. The helper then stops the authority (the existing fence sequence),
   verifies absence, re-reads the proof, verifies the nonce matches its
   request, and reports `QuiesceProven` in its observation.
5. The Manager treats `AuthorityAbsent && QuiesceProven` exactly as it
   treats `AuthorityAbsent && PriorStrictFenced` today: the epoch may
   advance. A **missing membership file on an established placement is
   lost evidence and refuses quiesce** — only the authority's own proof
   record means empty (the authority's first-start initialization
   behavior is never imitated by the checker).

Pinned file formats (both strict JSON, ≤ 4 KiB, atomic-write + fsync;
unknown fields refused):

- `ConfigRoot/<vol>/quiesce-request.json` (helper-written, root-owned,
  group-readable by the service GID so the authority sees it via its
  read-only bind): `{"nonce":"<64 hex chars>","requested_unix":N}`.
- `StateRoot/<vol>/quiesce-proof.json` (authority-written):
  `{"volume_id":"...","authority_epoch":N,
  "wire_session_epoch_hex":"...","nonce":"<hex>","membership_empty":true,
  "written_unix":N}`.

After stopping the authority the helper additionally re-reads the
membership file and requires it empty — both proofs must agree or the
quiesce fails closed. The helper removes both files when a quiesce is
cancelled; a fresh request nonce supersedes any stale proof.

No operator attestation exists in the archive/wake path for the normal
case. The exception path is honest and pre-existing: a volume whose
membership holds records for fenced mounts that will never `CleanDetach`
(a crashed client machine) cannot quiesce; recovering it is the existing
restart + operator strict-fence flow (`POST /v1/volumes/{id}/strict-fence`),
after which the volume is READY with an empty membership and archive
proceeds normally. Because the product's archive policy requires an idle
volume with no active mount enrollments — mounts detach cleanly at the end
of every Run in ordinary operation — the exception path is rare by
construction, and the quiesce refusal makes it visible rather than wedging.

### Consequences

- Cross-cell restore is native: wake placement is ordinary placement.
- Cell decommission: archive every volume (each becomes cell-independent),
  then retire the cell.
- **Cell abandonment** (`POST /v1/cells/{id}/abandon`, operator): declares
  a cell permanently lost. For each volume placed there: a volume whose
  archive the Manager has itself verified (state ARCHIVED, cursor `sealed`
  or `destroyed`) has its placement force-cleared with a durable
  Manager-side orphaned-placement record `{cell, tuple, epoch, "data
  orphaned, not proven destroyed"}` — the volume becomes placement-free
  ARCHIVED and can restore anywhere; ACTIVE/RESTORING volumes become
  QUARANTINED with the loss recorded (single-AZ reality, unchanged from
  v1). An abandoned cell ID is never re-registered; if the machine
  returns, its helper state no longer corresponds to any plan and fails
  closed, and the operator wipes and registers a fresh cell. This is what
  makes "cell/AZ loss cannot strand archived volumes" true rather than
  aspirational.
- Live migration of ACTIVE volumes stays out of scope; nothing here depends
  on it.

## 2. Volume lifecycle

```text
PROVISIONING -> READY <-> FENCING                      (existing, unchanged)
READY -> ARCHIVING -> ARCHIVED -> RESTORING -> READY   (READY at a later epoch)
READY | ARCHIVED -> DESTROYED                          (terminal, durable record)
QUARANTINED                                            (unchanged)
```

`ARCHIVING`, `ARCHIVED`, and `RESTORING` are first-class states in which an
absent authority is the **expected** observation; the v1 READY auto-fence
never fires for them. Every switch over `VolumeState` and
`cellplan.VolumePhase` becomes exhaustive with an error default.

### Canonical-representation invariant (one per state, explicit)

Canonical representation is keyed by `(State, ArchiveCycleStep)` — state
alone does not identify it while the cycle is mid-flight:

| State + cursor | Canonical representation |
| --- | --- |
| ACTIVE / ARCHIVING (any cursor through export) | XFS is canonical; the forming archive is not |
| ARCHIVED + `sealed`/`destroyed` | the sealed archive is canonical; a non-canonical cell copy still exists and is being destroyed/released |
| ARCHIVED + `released` | the sealed archive is canonical; no cell data exists |
| RESTORING | the layered composite: sealed immutable base + monotone hydration map + XFS-applied writes |
| post-convergence READY | XFS alone; restore mode ceases to exist |

The RESTORING composite is authoritative state, named as such. It is not
general copy-on-write: the base is sealed, the hydration map only ever gains
bits, and a write lands only after its chunk's hydration mark is durable
(ordering contract in restore-mode.md). Crash recovery is two lines:
durably marked ⇒ XFS canonical for that chunk; unmarked ⇒ re-fetch from the
sealed base (idempotent).

### Archive sequence

The Manager records a durable per-volume cursor (`ArchiveCycleStep`:
`quiescing → exporting → sealed → destroyed → released`). Every step is
idempotent and crash-resumable by Manager, agent, helper, or archiver.

**Preconditions, all checked before any state change.** An archive request
that fails one of these is refused with the volume still READY and the cell
plan unbumped; nothing is half-entered.

- **The Manager can verify.** A Manager started without archive credentials
  holds no verifier, so it could never complete step 3 and the volume would
  wedge at cursor `verifying` no longer serving. `ArchiveVolume` refuses
  such a request outright with `ErrArchiveStoreUnavailable` (503).
- **The cell can export.** The placement cell must report
  `archive_configured` (§4). A cell whose helper holds no readable
  archive-store credentials can neither export nor hydrate.
- **The cell has an archive slot.** See the per-cell caps in §5.

1. **Quiesce** (active, not timed; the authority stays up until membership
   is empty).
   1. Revoke all mount enrollments (`terminateVolumeEnrollments`) and stop
      issuing new grants (the mount gates refuse ARCHIVING volumes).
   2. Tear down Files-gateway sessions: the product driver and the Manager
      step both call the new `DELETE /v1/volumes/{id}/session` on every
      configured gateway, carrying a monotonically increasing per-volume
      fence value; the gateway records the floor and `PUT session` re-checks
      it after dialing, closing the install race (restore-mode.md).
   3. The plan enters phase `ARCHIVE`; the helper runs the authority
      quiesce protocol (§1): quiesce-request file → authority closes
      strict-attach admission → remaining mounts detach cleanly
      (`CleanDetach` still works — the authority is serving) → the
      authority writes the process-bound quiesce proof → the helper stops
      the authority, verifies absence, verifies the proof nonce, and
      reports `QuiesceProven`.
   4. A membership that does not empty within the product's patience means
      the archive is refused: the helper reports quiesce-not-proven, the
      Manager returns the volume to READY (phase back to SERVE), and the
      authority leaves quiesce mode (the helper removes the request file;
      the authority re-admits strict attaches — no restart happened on
      this path, so no epoch change). A membership stale from a fenced,
      never-detaching mount is recovered through the existing restart +
      operator strict-fence flow, then archive retries. Archive is
      refused, never committed-then-blocked.
2. **Export.** The Manager has durably allocated an `ArchiveAttempt` UUID
   on entering ARCHIVING. The plan's `ARCHIVE` entry carries
   `{attempt, key_version}` — identities, never object keys or paths: the
   helper derives every object key locally as
   `<root-pinned prefix>/<volumeID>/<epoch>-<attempt>/…` from
   root-provisioned cell configuration, preserving the
   no-network-selected-paths rule. The helper starts the per-volume
   archiver unit (restore-mode.md: read-only bind of the volume tree, own
   hardened unit, `Restart=no`). The archiver builds pack + manifest,
   uploads (multipart per pack-format.md), verifies every chunk digest by
   read-back, and writes its sealed result; the helper persists
   `ArchiveSealed{attempt, manifest ObjectRef, pack ObjectRefs, root
   digest, sealed totals}` **durably in its own state on the assignment
   before reporting it**, so `Observe` replays it byte-identically across
   helper restarts and plan-generation bumps. Phase exit requires the
   archiver unit absent (the same systemd + cgroup-empty proof used for
   the authority).
3. **Commit ARCHIVED — with independent verification.** The Manager holds
   its own narrow archive-store credentials (read/head/delete on the
   prefix; no write). Cursor `verifying` while it runs: it fetches the
   manifest (bounded, streaming), checks the footer self-digest, validates
   the entry graph and every table bound, confirms the recorded
   `{volumeID, epoch, attempt}`, and `HeadObject`s every pack, matching
   size — and the CRC64NVME full-object checksum where the store supports
   it. The archive-store configuration declares its checksum capability
   (`crc64nvme-full-object` requires `ChecksumType=FULL_OBJECT` uploads and
   checksum-bearing `HeadObject`; a store without it, e.g. some
   S3-compatibles, is declared `none` and verification covers presence and
   size). Full pack-content verification is the archiver's read-back pass;
   the archiver is cell TCB (§0), so the division of labor is: the TCB
   proves content, the Manager independently proves the manifest and
   object inventory before anything may be destroyed. Verification
   failures and store outages keep the cursor at `verifying` with
   retry/backoff — a visible, non-destructive stall (XFS remains
   canonical; abort stays available). Only on success does the Manager
   durably record the `ArchiveRecord` and transition to `ARCHIVED`
   (cursor `sealed`). This is a control-plane verification read, not a
   data-path role.
4. **Destroy.** Plan phase `DESTROY`. The helper performs five verified
   host operations: (1) remove the XFS project tree and zero the project
   quota record; (2) remove the per-volume sysusers conf (the account
   itself is retained); (3) remove and disable the systemd drop-ins;
   (4) remove the volume ConfigRoot; (5) remove the volume StateRoot.
   Phase entry requires archiver and hydrator units absent. The **destroy
   proof** is `SHA-256` over the canonical JSON (sorted keys, no
   insignificant whitespace) of a typed postcondition record:
   `{authority_epoch, authority_id, authority_server_name, cell_id,
   listen_port, placement_sequence, postconditions: {config_root_absent,
   dropins_absent, quota_cleared, state_root_absent, sysusers_conf_absent,
   tree_absent}, project_id, service_gid, service_uid, volume_id}` —
   postconditions only, never action history, so a retry after a partial
   crash re-verifies and produces the identical hash, and the identity
   fields bind the proof to this exact placement (the complete immutable
   assignment identity). The signed-plan digest is deliberately excluded:
   benign plan-generation refreshes (certificate rotation) would change it
   and break retry stability; producer authenticity comes from the TCB
   argument in §0, not from this hash.
   The helper persists the record on the assignment durably before
   reporting `DestroyProofSHA256`. Cursor `destroyed`.
5. **Release.** Plan phase `RELEASE`, echoing
   `{placement_sequence, authority_epoch, destroy_proof_sha256}`. The
   helper honors it against the **current assignment only**: the entry
   must match the assignment's placement sequence, epoch, and its own
   recorded destroy proof exactly; then it writes the durable tombstone
   `{volume_id, placement_sequence, authority_epoch,
   destroy_proof_sha256}` (overwriting any older tombstone for the
   volume), removes the assignment, and reports released. A `RELEASE`
   with no current assignment is an idempotent no-op **iff** it matches
   the stored tombstone exactly; anything else aborts reconciliation
   (fail closed — a stale plan replay can never touch a newer
   incarnation). The Manager then clears the volume's placement, prunes
   any remaining terminal mount-enrollment records for the volume, drops
   the volume from the cell plan, and frees the plan slot (cursor
   `released`). The volume is now placement-free `ARCHIVED`.

**Ordering invariant:** a verified copy exists at every instant. XFS is
canonical through step 3's commit; destroy runs only after the Manager's
own verification; between 3 and 5 two verified copies exist.

**Abort.** A wake during steps 1–2 cancels the archive: quiesce-phase
demand (membership still live or just emptied, authority still up) simply
returns the volume to READY with no epoch change; after the authority has
been stopped, the abort path is the ordinary machine-gated re-provision on
the **same placement** at epoch `e+1` (§1) — same identity tuple, same
endpoint name, fresh keys per the existing generation-bump flow. "Same
epoch after an authority stop" is explicitly not claimed: sessions and
replay slots died with the process, and the wire epoch is fresh either
way. The forming archive attempt is garbage-collected by attempt prefix;
attempt UUIDs are never reused, and phase exit proved the archiver absent,
so no stale uploader can write into a later attempt's keys.

A wake after step 3 proceeds as a restore — but **serialized behind the
cycle**: restore placement is admitted only at cursor `released`. A wake
request during `sealed`/`destroyed` accelerates destroy+release (they are
local host operations, seconds not minutes) rather than creating a second
placement; the single `Placement` pointer therefore never has to represent
two residences.

### Restore sequence

1. **Place** on any healthy cell in the volume's pool (§5 admission), at
   `PlacementSequence+1`, epoch `+1`, fresh identity tuple and endpoint
   name.
2. Plan phase `RESTORE` with `RestoreFrom{sealed_epoch, attempt,
   manifest_digest, pack_digests, sealed totals}` — again identities and
   digests, keys derived locally. The helper provisions exactly as
   `PROVISION` (sysusers with the per-placement name, directory, quota,
   keys, CSR, drop-ins), then runs the restorer (hydrator in
   namespace-restore mode): manifest download + digest verification,
   full namespace materialization, fsync. Namespace durability + manifest
   verification are the mount gate.
3. The authority starts in restore mode with the hydrator sidecar
   (restore-mode.md). The Manager admits mounts: `IssueMount`,
   `ReauthorizeMount`, and `RefreshMountEnrollment` accept
   `READY | RESTORING` in the same change.
4. Drain + demand recall run to convergence; the authority writes a durable
   convergence record and reports it; the Manager commits `READY` (plan
   returns to `SERVE` without restore configuration). Crash ordering and
   the no-re-enter guarantee are specified in restore-mode.md.
5. Archive objects are retained until the Manager has durably committed
   the convergence; only then are they GC-eligible (or retained as a
   checkpoint).

Durability note: RESTORING placements are ACTIVE placements for durability
purposes. The composite is authoritative; losing the cell mid-restore loses
exactly the writes made since wake — the same single-AZ semantics as any
ACTIVE volume. The sealed base still covers everything else, and wake
retries elsewhere.

### DESTROYED

Terminal deletion with a durable record. From `READY`: quiesce → destroy →
release, no export. From `ARCHIVED`: the Manager deletes the archive
objects with its delete-scoped credentials, then marks the record. The
`DESTROYED` volume record is retained (audit: who, when, prior state) and
pruned after a configured retention period; `GetVolume` returns it with
`state: DESTROYED` until then. Remaining enrollment records and receipts
referencing the volume are pruned at the transition. One path regardless of
deployment configuration; the product owns the retention window before it
calls destroy.

## 3. State schema v2 (Manager)

`StateSchemaVersion = 2`.

```go
type Volume struct {
    // Identity — stable for the volume's lifetime.
    ID, AuthorizationDomain, Owner, ProductIssuer, ProductPublicKeyPEM
    QuotaBytes, QuotaInodes         // safety ceilings; monotonically raisable
    AuthorityEpoch uint64           // renamed AuthorityGeneration; JSON key kept
    PlacementSequence uint64        // monotonic; 1 for a migrated v1 placement
    State VolumeState               // + ARCHIVING, ARCHIVED, RESTORING, DESTROYED
    Pool  string

    Placement *Placement            // nil exactly when no cell resources exist
    Archive   *ArchiveRecord        // non-nil from ARCHIVED commit until GC after convergence
    ArchiveCycleStep string         // "", quiescing, exporting, sealed, destroyed, released
    ArchiveAttempt   string         // UUID; allocated on entering ARCHIVING; never reused
    RestoreStep      string         // "", restoring-namespace, serving-restore, converged
    DestroyedUnix    int64          // set on DESTROYED; record pruned after retention
    CreatedUnix, UpdatedUnix, QuarantineReason
}

type Placement struct {
    CellID string
    Sequence uint64                 // == volume.PlacementSequence at creation
    ProjectID, ServiceUID, ServiceGID uint32; ListenPort uint16
    AuthorityID, AuthorityServerName string   // v-<id>-p<seq>.<zone>; equal
    AuthorityCSRPEM, AuthorityCertificatePEM string; AuthorityCertExpires int64
    PriorStrictFenced bool; StrictFenceEvidence string
    LastObservedUnix int64
    UsedBytes, UsedInodes uint64; UsedObservedUnix int64  // measured usage
    PendingBytes, PendingInodes uint64   // in-flight admission charge; see §5
    DestroyProofSHA256 string
}

type ObjectRef struct { Key string; SizeBytes uint64; SHA256 string; CRC64NVME string }

type ArchiveRecord struct {
    FormatVersion uint32; ChunkSizeBytes uint32
    Attempt string; SealedEpoch uint64; SealedUnix int64
    Manifest ObjectRef
    Packs    []ObjectRef            // max 1024 entries; keys <= 512 bytes
    RootDigest string
    LogicalBytes, LogicalInodes uint64          // display/product totals
    SealedAllocatedBytes, SealedInodes uint64   // admission sizing (pack-format.md)
    KeyVersion string
    SealedMeasuredBytes, SealedMeasuredInodes uint64  // measured usage at seal commit; 0 = unmeasured
}
```

`SealedMeasured*` is captured by the Manager at the instant the verified seal
commits, from the placement's last measurement. The volume is quiesced for the
whole cycle, so that reading is exact or a pre-quiesce lower bound — both safe
under the `max()` that restore admission applies (§5). Zero is a valid,
permanently supported value: records sealed before the field existed decode
zero and are charged from `SealedAllocatedBytes`/`SealedInodes` alone. It is
Manager-internal admission input and is deliberately absent from
`ArchiveSummaryView`, which stays the minimal product projection.

Bounds: `len(Packs) <= 1024`, `len(ObjectRef.Key) <= 512`, serialized
`ArchiveRecord <= 512 KiB`, and the helper's `ArchiveSealed` observation
payload `<= 768 KiB` — all comfortably inside the agent's 4 MiB observation
bound and the Manager's 1 MiB HTTP body bound, which rises to 2 MiB for the
cell-observation route in the same change.

Cells gain `Pool string` (required: `product`, `system`, or `test`),
`Decommissioning bool`, `UsageStaleAfter`-relevant freshness fields, and
lose `AllocatedBytes`/`AllocatedInodes` entirely. Product-role
`createVolume` can never land on a `test` pool.

### Validator v2

- Placement uniqueness (project/UID/port per cell) and the allocator
  boundary apply to volumes **with** placements.
- `Placement == nil` requires state `ARCHIVED` (with `Archive != nil` and
  cursor `released`) or `DESTROYED`.
- Enrollment cross-binding (cell/authority-ID/epoch equality) is enforced
  **only for ACTIVE enrollments**, and an active enrollment requires the
  volume to have a placement whose fields it matches. Terminal enrollment
  records validate against volume identity only (volume present,
  owner/domain/issuer match); RELEASE and DESTROYED prune them.
- The entitlement-sum invariant is removed, not reformulated (§5).
- `MaxVolumesPerCell` counts placements.
- `DESTROYED` volumes must have `Placement == nil`, `Archive == nil`, and
  `DestroyedUnix > 0`.

### Offline migration v1 → v2

`portablefs-manager migrate-state`: read the v1 file under the v1 validator
(the loader gains per-version validator dispatch), transform — `Pool:
"product"`, `AuthorityEpoch := AuthorityGeneration`, `PlacementSequence :=
1`, `Placement` extracted from the flat fields (keeping the v1 endpoint and
account names), usage fields zeroed, v1 `RETIRED` volumes stay `RETIRED`
(pre-existing retirements keep their preserved-data semantics; new code
paths use ARCHIVED/DESTROYED) — and write a fresh single-record v2
compacted snapshot to a new file, installing it atomically. The v1 file is
preserved unmodified as the rollback artifact. A v2 manager refuses a v1
state file with instructions; the gate is one-way and lives in the release
runbook.

## 4. Cell plan v2 and helper contract

`cellplan.Version = 2`, token prefix `v2.`, signature domain
`portablefs-cell-plan-v2\0` — a v1 verifier cannot mistake a v2 envelope
and vice versa. Phases: `PROVISION`, `SERVE`, `FENCE`, `RETIRE` (retained),
`ARCHIVE`, `RESTORE`, `DESTROY`, `RELEASE`.

Releasing a volume from a cell touches four seams that today jointly forbid
it; they change together in this contract:

1. the helper's leaving-plan abort (`reconciler.go:109-113`) becomes the
   tombstone rule of §2 step 5;
2. the Manager's "cell omitted an assigned volume observation" quarantine
   (`manager.go:492-503`) treats a helper-reported release as
   expected-absent;
3. the agent's plan/observation set-equality check (`agent.go:123-142`)
   accepts a released-volume report for a `RELEASE` entry;
4. the validator's entitlement-sum equality (`types.go:563-567`) is removed
   by §5.

Plan payload hygiene: v2 hoists `AuthorityCAPEM`, `ClientCAPEM`, and
`CapabilityPublicKey` to plan level (they are Manager-wide and identical
per volume — the dominant term in the ≈2.2 KiB per-entry size behind the
~1,399-entry payload ceiling). With release freeing slots and CA material
hoisted, plan payload scales with live volumes.

`VolumePlan` v2 adds: `PlacementSequence`, `ArchiveTo {attempt,
key_version}`, `RestoreFrom {sealed_epoch, attempt, manifest ObjectRef
digests, sealed totals}`, `ReleaseProof {placement_sequence, epoch,
destroy_proof_sha256}` — identities and digests only; the helper derives
object keys locally from root-pinned configuration (§2 step 2), preserving
the no-network-selected-input rule verbatim.

Helper state v2 (`helperStateVersion = 2`):

- `Assignment` replaces `QuotaApplied bool` with
  `AppliedQuotaBytes/AppliedQuotaInodes uint64`; the helper re-runs
  `xfs_quota limit` exactly when signed > applied and refuses signed <
  applied (monotonic raise only). `immutableAssignmentMatches` allows
  increases in exactly `{QuotaBytes, QuotaInodes}`.
- `Assignment` gains `PlacementSequence`, `ArchiveSealed` (durable seal
  replay record), and `DestroyProof` (durable postcondition record).
- New `Tombstones map[volumeID]Tombstone{PlacementSequence, Epoch,
  DestroyProofSHA256}` — latest release only.
- Admission of a new assignment for a tombstoned VolumeID requires
  `PlacementSequence > tombstone.PlacementSequence` (and, transitively,
  a fresh identity tuple by allocator construction).

Rollout is a release gate, mechanically enforced: **helper → agent →
manager.** The v2 helper reads v1 and v2 state and verifies v1 and v2
envelopes, but keeps writing v1-shaped state until it first applies a v2
plan (the dual-write gate) — so helper and agent binaries can be rolled
back freely until the manager starts signing v2. Capability is explicit,
never inferred from release-ID strings: the cell observation gains
`plan_versions: []uint32` and `helper_state_versions: []uint32` (the
helper declares its own; the agent relays them and appends its own plan
versions). The manager signs a v2 plan for a cell only when that cell's
last durable observation declares plan version 2 for both helper and
agent; until then it signs v1 plans containing only v1-expressible
phases. Archive/restore for volumes on a cell is gated on that cell's v2
plan capability.

The same observation carries one further capability, on the same
declared-never-inferred rule: `archive_configured: bool`. The helper answers it
on every status pass, true exactly when its configured archive-credentials path
is non-empty and names a file that is present, non-empty, and unreadable by
group and other — the same shape the helper will demand when it stages those
credentials for an archiver or hydrator unit. It is a live fact, not a durable
one: revoking the file stops new archive and restore placement on the next
poll. The Manager stores it on the cell and requires it for `ArchiveVolume` and
for restore admission; ordinary create placement does not require it. Absent
from persisted state it decodes `false`, which refuses archive work until the
cell reports otherwise — correct and safe under rollback.

## 5. Capacity model

Removed: the hard sum-of-entitlement invariant and entitlement-sum
admission. Replaced by measured usage plus bounded in-flight charges.

- **Measurement.** `VolumeObservation` gains `UsedBytes`/`UsedInodes`.
  Mechanism: `fstatfs` on the project directory. For a directory carrying a
  project ID and `PROJINHERIT` with hard limits set, XFS
  (`xfs_qm_statvfs`) rewrites `f_blocks/f_bfree/f_files/f_ffree` to the
  project's limits and usage — the exact mechanism the authority's own
  `Volume.StatFS` documents and relies on
  (`vcs/internal/xfsstore/metadata_linux.go:212-250`, verified on Linux
  6.8), and the provision-verify path already opens this descriptor. Used
  = `(f_blocks - f_bfree) * f_bsize`; inodes analogous. Zero new
  privileged surface. The stale sentence in
  `xfs-authority-architecture.md:438-444` ("statfs retains cell-wide
  meaning") describes only the no-limit case and is amended by this plan;
  a real-XFS test pins the per-project reading.
- **In-flight charges.** Every placement carries a durable
  `PendingBytes/PendingInodes` charge set at admission. A create charges
  the configured provision floor and clears the charge at the first usage
  observation with `UsedObservedUnix > placement.CreatedUnix`. A restore
  charges the archive's sizing requirement — `ceil(1.05 × base) + 64 MiB`
  and `baseInodes + 1024` (constants are configuration with these
  defaults), where `base = max(SealedAllocatedBytes, SealedMeasuredBytes)`
  and `baseInodes = max(SealedInodes, SealedMeasuredInodes)`: the archive's
  packed sizing and the tree's measured allocation at seal time can each
  understate the other, so admission charges the larger before overhead
  (§3) — and the charge is **retained until
  the Manager has committed convergence**, then cleared by the first
  post-convergence measurement: the early namespace is sparse and the
  drain grows toward the sealed totals, so a pre-convergence measurement
  must not release capacity the drain is about to consume. `Sealed`
  totals themselves are pinned in pack-format.md (block-rounded stored
  extents at 4096-byte granularity plus 4096 bytes of metadata allowance
  per entry; `SealedInodes` = entry count). This closes the
  serialized-double-admit hole without reintroducing lifetime entitlement
  reservation.
- **Admission.** A cell is eligible only if: not quarantined, not
  decommissioning, `cellFresh` (live heartbeat at the current plan
  generation), and its newest usage observation is younger than the
  configured `UsageStaleAfter`; otherwise admission fails closed for that
  cell. Restore admission additionally requires the cell to declare plan
  version 2 **and** `archive_configured` (§4); create admission requires
  neither. Then:
  `Σ_over_placements charge(p) + incoming + reserve ≤ capacity`, where
  `reserve` is the configured cell reserve fraction and per placement
  `charge(p) = max(measured used, pending, provision floor)` — a
  placement lacking a fresh measurement of its own always contributes at
  least `max(last measured, pending, floor)`, never zero, so one freshly
  measured placement cannot launder an unmeasured sibling's usage.
  **Per-placement staleness is charged at quota.** The cell-level freshness
  gate does not cover one placement whose own measurement froze while its
  cell kept heartbeating — a host measurement failure on a single volume is
  exactly that shape. When
  `now - max(placement.UsedObservedUnix, placement.CreatedUnix) >
  UsageStaleAfter`, that placement is charged
  `max(volume.QuotaBytes, pending, floor)` (and `QuotaInodes` for inodes)
  instead of the reading nobody is refreshing. A new placement therefore has
  one `UsageStaleAfter` grace window from `CreatedUnix` and is charged at its
  quota ceiling after that until it is measured.
- **Per-cell archive and restore concurrency.** An archiver and a hydrator
  are each a full-tree-I/O process colocated with live volume authorities,
  and nothing else bounds how many a cell may run. Two configured caps do:
  `MaxArchivingPerCell` (default 2, `-max-archiving-per-cell`) and
  `MaxRestoringPerCell` (default 4, `-max-restoring-per-cell`); both must be
  positive.
  - `ArchiveVolume` counts, on the placement's cell, volumes in `ARCHIVING`
    at cursor `quiescing` or `exporting`. Cursor `verifying` does **not**
    count: phase exit already proved the archiver unit absent, and the only
    outstanding work is the Manager's own archive-store verification, which
    burdens the Manager rather than the cell. At the cap the request is
    refused with `ErrBusy` and **no state change**, so a product sweep simply
    retries the unchanged request on its next pass.
  - Restore admission skips any cell already holding `MaxRestoringPerCell`
    `RESTORING` placements. The skip is evaluated **after** every eligibility
    and capacity check, so a cell rejected there is known to be otherwise
    able to hold the placement.
  - Busy is not capacity. If every candidate cell was passed over only for
    the restore cap, admission returns `ErrBusy` (retry unchanged), not
    `ErrCapacity` (the fleet cannot hold this volume). `WakeVolume`
    propagates whichever it gets, unaltered.
  - `GET /v1/capacity` keeps its simple probe: `RestoreAdmissible` is
    "a restore would be admitted right now", so a fleet that is merely
    saturated reports `false` exactly as an exhausted one does. The report
    is a per-pool sizing view, not a diagnosis of why a single request would
    be refused; the caller's error carries that distinction.
- **Restore priority.** When post-admission headroom would fall below the
  configured wake-burst envelope, creates are refused with `ErrCapacity`
  while restores are still admitted. Fleet policy holds headroom ≥ the
  wake-burst envelope and autoscales before thresholds; alerts fire far
  earlier.
- **Placement choice:** least measured+pending load within the volume's
  pool. The warm-cache preference for a recently departed volume's
  previous cell is a pure optimization hint, deferred until wake p95
  demands it.
- **Operations:** cell registration requires the pool label;
  `PATCH /v1/cells/{id}/capacity` (monotonic raise, for online EBS
  growth); `POST /v1/cells/{id}/decommission`; `GET /v1/capacity` returns
  per-pool capacity, measured use, pending charges, placement and archived
  counts, and admission verdicts. `/healthz` is untouched.
- Per-volume quotas remain safety ceilings: high, measured, monotonically
  raisable; the inode guard stays; its full value is never reserved.

## 6. Explicitly deferred

Live migration of ACTIVE volumes; incremental checkpoints (the format is
ready); cross-pack dedup; access-order pack sorting; IA/Glacier tiering;
sub-chunk block granularity; continuous two-way sync (never — checkpoints
are the sanctioned future); multi-region.
