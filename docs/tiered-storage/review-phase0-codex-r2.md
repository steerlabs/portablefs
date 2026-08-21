# Phase-0 tiered-storage revision-2 verification

Reviewed against worktree commit `4b3c499842ee`. This review compares findings
1–31 in `review-phase0-codex.md` with revision 2 of
`identity-lifecycle-and-capacity.md`, `pack-format.md`, and the new
`restore-mode.md`. The specs were not edited.

Revision 2 resolves 22 findings, partially resolves 8, and leaves 1 unresolved.
It is not ready to freeze. The replacement archive gate is not an authenticated
or atomic proof, enrollment revocation can make strict membership permanently
nonempty, a dead cell can strand a verified archive before `RELEASE`, and the
restore map has a crash bug on fetch-free overwrites. The measured-capacity and
rollout gates also need more work.

## Finding-by-finding verification

1. **UNRESOLVED: archive and destroy observations are forgeable by the
   unprivileged cell agent.** Revision 2's §2, “Archive sequence,” step 3 adds
   Manager-side manifest and object verification, which keeps an agent from
   claiming that nonexistent archive objects are sealed. It does not
   authenticate `StrictMembershipEmpty`, `AuthorityAbsent`,
   `DestroyProofSHA256`, or `released` as root-helper output. Today the helper
   returns JSON to the agent, the agent may alter it, and the Manager
   authenticates the agent's cell credential. Steps 4 and 5 still let those
   unauthenticated fields cause placement destruction and release. Worse, §1
   now lets the helper-reported empty bit replace operator-controlled
   `PriorStrictFenced` for an epoch advance. Manager verification of S3 objects
   cannot authenticate host absence or mount absence. The original requirement
   for a helper-held attestation key, or an equivalent Manager-verifiable helper
   channel, remains.

2. **RESOLVED: authority epoch named two values.** Exact resolving section:
   `identity-lifecycle-and-capacity.md` §1, “Identity model,” especially the
   four-identity diagram and the “Authority epoch” paragraph. It keeps the
   durable `authority_generation` counter separate from the random 16-byte wire
   session epoch and says process restart always mints a new wire epoch.

3. **RESOLVED: pre-seal abort reused an epoch after stopping the authority.**
   Exact resolving sections: §2, “Archive sequence,” step 1, and §2, “Abort.”
   Membership now empties while the old authority serves. An abort before stop
   returns to `READY` at the same epoch; an abort after stop follows the normal
   same-placement generation bump to `e+1`. The new quiesce implementation has
   separate safety and liveness faults, recorded below, but it no longer claims
   that a killed authority can restart at the same epoch.

4. **RESOLVED: epoch-bearing endpoint conflicted with immutable assignment.**
   Exact resolving section: §1, “Identity model,” the “Placement” and
   “Authority endpoint names” bullets. Endpoints now include the placement
   sequence, stay stable across within-placement epoch advances, and change only
   for a fresh placement. Placement sequence 1 keeps its unsuffixed endpoint.

5. **RESOLVED: retained service account blocked a fresh same-cell UID.** Exact
   resolving section: §1, “Identity model,” the per-placement account-name
   bullet. The new account is a 128-bit truncated hash of volume and placement
   sequence, so the retained prior account has a different name.

   The resulting name has 30 characters: four for `pfs-` and 26 base32
   characters. That fits systemd's 31-character portable user/group-name rule;
   the spec's “32-char Linux account-name bound” is imprecise, although harmless
   for this formula. Current shadow-utils `useradd` allows much longer names, so
   `useradd` is not the limiting component. See systemd's
   [User/Group Name Syntax](https://systemd.io/USER_NAMES) and the current
   [`useradd(8)` caveat](https://man7.org/linux/man-pages/man8/useradd.8.html).
   A 128-bit truncation gives an approximate birthday collision probability of
   1.5×10^-21 at one billion placements. A collision fails closed because
   `verifyServiceIdentity` checks name→UID/GID and UID/GID→name in both
   directions. It cannot silently adopt the other account.

6. **RESOLVED: one `Placement` could not represent wake racing post-seal
   cleanup.** Exact resolving section: §2, “Abort,” final paragraph. Restore
   admission is serialized behind cursor `released`; a wake at `sealed` or
   `destroyed` accelerates cleanup and does not allocate a second placement.
   That fixes the schema race. The absence of a dead-cell release path makes
   this serialization an unbounded wait in one important case; see new finding
   R2-3.

7. **RESOLVED: clearing placement conflicted with terminal mount enrollments.**
   Exact resolving sections: §2, “Archive sequence,” step 5, and §3, “Validator
   v2.” Terminal enrollment records validate against volume identity rather
   than current placement fields, and `RELEASE`/`DESTROYED` prune them.

8. **RESOLVED: tombstone matching across repeated same-cell incarnations.**
   Exact resolving sections: §2, “Archive sequence,” step 5, and §4, “Helper
   state v2.” A release consumes only the exact current assignment; a no-op
   replay must exactly match the stored tombstone; a new assignment must carry a
   greater placement sequence.

9. **PARTIALLY RESOLVED: destroy proof canonicalization.** §2, “Archive
   sequence,” step 4 now defines canonical JSON over postconditions rather than
   action history, and it requires durable helper storage before reporting.
   Retry after a partial crash can therefore reproduce the same value.

   The record is still not bound to the signed plan digest or plan generation,
   although the original finding required both. It also omits fields from the
   claimed “full placement tuple,” including `service_gid`, `authority_id`, and
   `authority_server_name`. The exact proof type should bind all immutable
   assignment identity plus the applied plan digest/generation. Authentication
   of the proof producer remains finding 1.

10. **RESOLVED: archive object keys reused after abort.** Exact resolving
    sections: §2, “Archive sequence,” step 2 and “Abort,” plus
    `pack-format.md` opening contract and §“S3 mechanics.” Every attempt gets a
    never-reused UUID and prefix; phase exit proves the archiver unit absent;
    garbage collection targets the attempt prefix; conditional create is an
    extra store-side guard.

11. **RESOLVED: archive success lacked durable replay state.** Exact resolving
    sections: §2, “Archive sequence,” step 2, and §4, “Helper state v2.”
    `ArchiveSealed` is persisted on the helper assignment before observation and
    replayed byte-identically across helper restarts and plan-generation bumps.

12. **RESOLVED: archive/restore accepted network-selected storage paths.**
    Exact resolving sections: §2, “Archive sequence,” step 2, and §4, “Cell plan
    v2 and helper contract.” Plans carry attempt/key-version identities and
    digests. The helper derives keys from a root-pinned prefix plus volume,
    epoch, and attempt.

13. **RESOLVED: archiver could mutate canonical XFS or survive phase exit.**
    Exact resolving sections: `restore-mode.md` §“Components” and lifecycle §2,
    “Archive sequence,” steps 2 and 4. The archiver receives a read-only data-dir
    bind, runs in its own hardened `Restart=no` unit, and must be absent with an
    empty cgroup before phase exit, authority restart, or destroy.

14. **PARTIALLY RESOLVED: restore correctness contract was missing.** The new
    `restore-mode.md` substantially fills the gap. Exact resolving sections are
    §“Hydration map,” §“Recall semantics,” §“Drain,” and §“Named degraded
    states.” They define restored-inode keyed bits, hardlink behavior,
    rename/unlink/truncate handling, the base-write/map-write/user-write order,
    recall deadlines, nonfatal restore errors, and a durable convergence
    protocol.

    One written crash rule is unsafe. For a whole-chunk overwrite and `O_TRUNC`
    to zero, §“Hydration map,” rule 3 durably marks the chunk before applying the
    mutation. A crash after map `fsync` but before the user mutation leaves a
    marked chunk whose XFS bytes are still the sparse placeholder, not the old
    sealed bytes. Losing an unacknowledged mutation does not permit losing the
    pre-mutation file contents. The same section also says “single-flight per
    chunk” without requiring drain, demand recall, truncate, and write to hold
    one chunk state-machine lock through a final marked-state recheck and the XFS
    operation. A late drain `pwrite` can otherwise overwrite a user mutation.
    This remains a restore correctness blocker.

15. **PARTIALLY RESOLVED: `fstatfs` measurement and the existing filesystem
    contract.** Lifecycle §5, “Capacity model,” now gives the XFS mechanism:
    `xfs_qm_statvfs` rewrites `statfs` results for a `PROJINHERIT` directory with
    project hard limits. That matches the current implementation comments and
    real-XFS test in `vcs/internal/xfsstore/metadata_linux.go:212-250` and
    `project_linux_test.go:64-89`; the multiplication error in the original
    review does not apply under those conditions.

    The repository's current normative documents still say `statfs` is
    cell-wide (`docs/failure-modes.md:210-217` and
    `docs/xfs-authority-architecture.md:438-444`). Calling those sentences
    “amended by this plan” does not amend them. The contracts must be changed in
    the same freeze change, with the no-hard-limit case stated separately.

16. **PARTIALLY RESOLVED: measured admission had no reservation.** Exact
    resolving section: lifecycle §5, “In-flight charges” and “Admission.” Every
    new placement now creates a durable pending charge and admission uses
    `max(measured, pending)`, closing the immediate double-create example.

    The charge clears too early for restore. The first observation after
    `Placement.CreatedUnix` may see only the sparse namespace while background
    drain still has nearly all sealed data left to allocate. Clearing the full
    restore charge at that observation exposes the same capacity to later
    admissions, then drain consumes it. Minimal fix: retain the restore charge
    through durable convergence and clear it only on a successful usage
    observation taken after that convergence record. Until then, admission must
    use at least the full sealed requirement plus headroom, not the first
    measured value.

17. **PARTIALLY RESOLVED: stale/offline observations.** Lifecycle §5,
    “Admission,” requires a current-plan heartbeat and a cell usage observation
    younger than `UsageStaleAfter`, so an offline cell with a durable old
    `HEALTHY` value is no longer eligible.

    Freshness is stated at cell level rather than for every placement. A
    placement with a missing measurement contributes its pending charge, but
    that charge may already be zero under the clearing rule. One freshly
    measured placement can therefore make the cell's “newest usage observation”
    fresh while another live placement contributes zero. Require a fresh,
    successful measurement for every placement, or retain a nonzero conservative
    charge for every placement lacking one.

18. **PARTIALLY RESOLVED: logical totals used as exact restore sizing.** Exact
    resolving sections: `pack-format.md` §“Manifest,” header, and lifecycle §5,
    “In-flight charges.” Display-only logical totals are now separate from
    `SealedAllocatedBytes`/`SealedInodes`, and restore admission adds metadata
    headroom.

    The accounting contract is not yet reproducible. “Block-rounded sum” plus
    “measured directory, symlink, and inode metadata blocks” does not name the
    syscalls, units, treatment of shared filesystem metadata, overflow rules, or
    what happens when target-XFS metadata layout differs. The “fixed metadata
    headroom factor” has no value, rounding rule, configuration identity, or
    plan field. Phase 0 should pin that algorithm and parameter before treating
    the totals as an admission guarantee.

19. **PARTIALLY RESOLVED: v2 helper/agent/manager rollout.** Lifecycle §4,
    “Cell plan v2 and helper contract,” now defines `v2.` envelopes, a distinct
    signature domain, helper dual-read behavior, the first-v2-plan write gate,
    rollout order, and the rollback boundary.

    The Manager cannot infer “v2-capable” from `LastHelperRelease` or
    `LastAgentRelease`: current release IDs are opaque validated strings with no
    version ordering or capability registry. The observation needs explicit
    supported plan/state versions (for example `plan_versions:[1,2]` and
    `helper_state_versions:[1,2]`), or the Manager needs a pinned allowlist that
    maps exact release IDs to capabilities. A naming convention alone is safe
    only if its grammar and comparison order become part of this contract.

20. **PARTIALLY RESOLVED: archive metadata bounds.** Lifecycle §3, “State
    schema v2,” now caps pack count, object-key length, serialized archive
    record, helper result, and the observation route. This addresses the
    Manager-state, plan, observation, and HTTP list growth cited originally.

    The binary manifest itself remains unbounded. `pack-format.md` records
    entry/frame/chunk counts but does not give their integer widths (apart from
    `parentIndex`), maxima, a manifest byte limit, individual raw-name or extent
    count limits, or the Manager/hydrator download and allocation bounds. A
    512-KiB `ArchiveRecord` may point at a manifest large enough to exhaust a
    verifier before it can reject it. Bound the manifest and each table before
    allocation.

21. **RESOLVED: entries lacked parent identity.** Exact resolving section:
    `pack-format.md` §“Manifest,” entry table. It defines root entry 0,
    `parentIndex < own index`, raw one-component names, duplicate rejection, and
    acyclicity by construction.

22. **RESOLVED: shared-frame identity was mixed with file-slice identity.**
    Exact resolving sections: `pack-format.md` §“Manifest,” entry table and
    frame table. Frame location, lengths, and checksum now live in the frame
    table; each file slice has its own offset, length, digest, and extent map.

23. **RESOLVED: sparse chunks lacked logical placement.** Exact resolving
    section: `pack-format.md` §“Chunking,” especially the fixed logical chunk
    bands and per-chunk extent list. It defines hole-only and partial-hole
    chunks, stored-byte ordering, digest input, full logical size, and hole
    reconstruction.

24. **RESOLVED: hardlink and dedup identities shared hydration state.** Exact
    resolving sections: `pack-format.md` §“Compression and pack layout,” dedup
    bullet, and `restore-mode.md` §“Hydration map.” Archive content source,
    restored inode, and logical chunk are distinct. Hardlink aliases share one
    restored inode; unrelated deduplicated files have independent map bits.

25. **RESOLVED: raw chunks broke stock-zstd recovery.** Exact resolving
    sections: `pack-format.md` §“Compression and pack layout” and
    §“Verification.” Packs now contain only valid zstd frames, using zstd raw
    blocks for incompressible input, and the stock decoder test covers them.

26. **RESOLVED: multipart boundaries could violate S3 limits.** Exact resolving
    section: `pack-format.md` §“S3 mechanics.” Parts are chosen after compression,
    contain whole frames, keep every nonfinal part between 8 MiB and 5 GiB, and
    shard using compressed size plus the 10,000-part cap.

27. **RESOLVED: checksum roles and manifest seal disagreed.** Exact resolving
    sections: `pack-format.md` §“Manifest,” footer, and §“Checksum roles.” The
    footer hashes every preceding manifest byte; whole-pack SHA-256 and
    CRC64NVME have distinct roles; frame and slice checksums cover named byte
    ranges; the Manager `ObjectRef` records manifest identity.

28. **RESOLVED: ownership and ctime could not round-trip.** Exact resolving
    sections: `pack-format.md` §“Manifest,” entry table, §“Identity contract,”
    and §“Verification.” Source UID/GID are absent, all restored inodes use the
    new placement principal, ctime is archive-only metadata, and equality tests
    compare mtime rather than ctime.

29. **RESOLVED: Files-gateway session installation raced eviction.** Exact
    resolving sections: lifecycle §2, “Archive sequence,” step 1.2, and
    `restore-mode.md` §“Quiesce.” `DELETE` advances a per-volume floor and `PUT`
    rechecks it after dial and before install. The floor is only in memory, but
    it is defense in depth: grant issuance stops, deletes retry, and authority
    stop terminates the gateway's uncached authority session. No kernel cache or
    durable membership depends on the gateway result.

30. **RESOLVED: convergence and `READY` commit order were not crash-defined.**
    Exact resolving section: `restore-mode.md` §“Drain,” “Convergence commit
    protocol.” It orders and fsyncs the local convergence record before
    observation, permanently disables restore mode when that record exists,
    commits Manager `READY` before archive GC, and defines replay at every crash
    interval.

31. **RESOLVED: `DESTROYED` meant both a record and no record.** Exact resolving
    sections: lifecycle §2, “DESTROYED,” and §3, “Validator v2.” `DESTROYED` is a
    retained terminal record with audit data and a configured pruning period;
    `GetVolume` returns it until pruning, and the transition removes references
    that would otherwise outlive it.

## New revision-2 findings

### R2-1. [BLOCKER] The machine-gated epoch advance is neither authenticated nor atomic

Current `ObserveCell` advances a fenced volume only when
`AuthorityAbsent && PriorStrictFenced` (`manager.go:475-488`). The Manager owns
`PriorStrictFenced`; an operator sets it through the strict-fence endpoint. By
contrast, revision 2 substitutes two fields that travel helper → unprivileged
agent → Manager. The agent can forge both unless the Manager can verify a
helper signature. This is the unresolved part of finding 1.

Even with an honest agent, `AuthorityRunning && StrictMembershipEmpty` is a
time-of-check/time-of-use observation. The authority may admit a previously
issued strict grant after the helper reads empty and before `host.fence` kills
the service and socket. Membership activation then lands after the reported
empty state. Separate observations of “empty while running” and “absent later”
do not prove that the set stayed empty across the transition.

The on-disk facts are usable, but the spec must define how:

- `visibility_membership.go` accepts exactly header `PFS-VISIBILITY-1`, a second
  line containing the hex-encoded volume ID, then unique nonzero 16-byte session
  IDs in hex. Malformed, duplicate, zero, wrong-volume, non-private, or
  non-regular files fail closed.
- The authority's loader treats a missing file as first-start initialization and
  creates an empty record. The archive checker must not copy that behavior. A
  missing membership file on an established placement is lost evidence and must
  refuse quiesce, not mean empty.
- The per-volume StateRoot is `0700` and service-UID-owned
  (`cellhost/host_linux.go:228-235`); the root helper can traverse and read it
  because root bypasses ordinary DAC. That part is sound. The file itself is
  private and atomically replaced.
- The authority holds the membership `.lock` for its process lifetime. A helper
  that merely opens the data file gets a complete old or new file but no
  exclusion against the next `Activate`. It cannot acquire the same exclusive
  lock while also proving the authority is still serving.

A safe gate needs an authority-side quiesce operation that first rejects new
strict attaches, drains clean detaches, and returns an empty-set proof bound to
the process/wire epoch. The helper must then stop that exact process, re-read the
record after absence, and attest the combined result with plan digest,
generation, volume, placement, and authority epoch. The Manager should advance
only after verifying that attestation.

### R2-2. [BLOCKER] Enrollment revocation can make membership nonempty forever

Lifecycle §2 step 1 says the Manager first revokes enrollments, mounts then
detach cleanly, and membership empties. Current failure semantics do not promise
that sequence. A fenced strict mount deliberately remains in the membership
file (`docs/failure-modes.md:170-191`). Only authenticated `CleanDetach` after
exact kernel and serving-connection absence calls `Deactivate`.

Linux automatic renewal is favorable but not guaranteed: on denial it retries
unmount and then `Mount.Close` attempts the evidence-bearing detach while the
authority still lives (`mountcmd.go:1766-1810,1834-1849`;
`fusev3/coherence_linux.go:1026-1091`). If unmount takes too long, the grant or
session can expire first, and delivery becomes fencing rather than clean detach.

The macOS path is more direct. Renewal denial first calls `d.fail`, closing the
strict authority session (`portablefsd/v3attach.go:583-600`). The FSKit watchdog
then makes the cached mount unservable, but a later detach skips
`DetachAfterUnmount` when the data plane is already terminal
(`v3attach.go:803-891`). The authority fences that participant and retains its
membership record, exactly as the failure contract requires.

The advertised patience path does not recover. Returning the volume to `READY`
keeps the same live authority, but the stale durable record remains. Every later
archive attempt sees nonempty membership forever, and revision 2 forbids the
operator-attested escape in the archive path. The contract needs a planned
quiesce protocol sent to mount supervisors before enrollment revocation, plus an
authenticated way to record mount absence after renewal has been disabled. If a
mount is already fenced, archive must either use the existing operator/host
fence proof or state plainly that it cannot proceed.

### R2-3. [BLOCKER] A dead cell strands an `ARCHIVED` volume before release

The Manager commits state `ARCHIVED` at cursor `sealed`, while the old placement
still exists and the helper must execute `DESTROY` and `RELEASE`. Wake is
serialized behind cursor `released`. If the cell fails permanently after seal
verification but before either helper action, the sealed archive is safe and
complete, yet no helper can create the tombstone or remove the assignment. The
volume can never reach `released`, so it can never restore elsewhere.

No Manager operation force-clears such a placement, even after operator
decommission and independent archive verification. This contradicts §1,
“Consequences” (“Cell/AZ loss cannot strand archived volumes”) and turns the
§2 wake serialization into an unbounded outage. Add a dead-cell release
protocol for a verifiably sealed archive. It needs a durable Manager tombstone
for the abandoned placement, allocator non-reuse forever, plan behavior if the
cell later returns, and an explicit statement that old cell data is orphaned
rather than proven destroyed.

### R2-4. [BLOCKER] Fetch-free restore mutations can make a false durable mark

`restore-mode.md` §“Hydration map,” rule 3 says to fsync the mark before applying
a whole-chunk overwrite or zero truncate. At that point XFS still contains the
sparse restore placeholder. A crash leaves a durable “XFS canonical” bit but no
base bytes and no user mutation. On restart the authority skips archive recall
and serves zeros.

The minimal safe order is apply the complete replacement, make that replacement
durable, then persist the mark, then acknowledge. If strengthening every aligned
write to `fdatasync` is unacceptable, the format needs a recoverable intent
state rather than one monotone bit. All recall, drain, truncate, and write paths
must also share a per-inode/chunk lock and recheck the bit after acquiring it;
“single-flight” for fetch alone does not stop a drain write from landing after a
user write.

### R2-5. [MAJOR] Manager archive verification does not verify pack SHA-256

The Manager fetches and hashes the manifest, but it only `HeadObject`s packs and
compares size plus CRC64NVME. That proves object presence and catches accidental
transport/storage corruption under the assumed store. It does not independently
check the end-to-end pack SHA-256 that the checksum table calls object identity,
nor does it validate chunk bytes against the manifest. The text “independent
verification” and “a forged or corrupt observation ... cannot fake durability”
is therefore stronger than the described check.

CRC64NVME itself is comparable for AWS multipart uploads when the upload uses
full-object checksum mode. AWS documents CRC64NVME as full-object-only and makes
the stored value available through checksum-enabled object metadata; see
[Checking object integrity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)
and [CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html).
The implementation contract should require `ChecksumType=FULL_OBJECT`, provide
the whole-object CRC at completion, request checksum metadata on `HeadObject`,
and pin base64/byte-order representation. An unspecified “S3-compatible” store
may lack these AWS features, so registration needs an exact capability probe or
the contract must require AWS S3 semantics.

This check creates a new availability dependency: an S3 or KMS outage blocks the
`ARCHIVED` commit. That is safe because XFS remains canonical until the commit,
and §2 permits an `e+1` abort after authority stop. It is an acceptable
fail-closed coupling, but it should appear as a named `ARCHIVING_VERIFY_BLOCKED`
state with retry and abort behavior rather than an implied quick control-plane
read.

### R2-6. [MAJOR] `RootDigest` omits restored filesystem semantics

`pack-format.md` §“Checksum roles” hashes only `(parentIndex, name, type,
contentDigest)` for each entry. It omits mode, mtime, symlink target, logical
size, sparse extent map, and hardlink grouping. Two archives that restore to
observably different filesystems can therefore have the same claimed whole-tree
identity. Hash the canonical semantic entry encoding, or hash the complete
sealed entry/chunk tables after excluding physical pack locations. The Manager
record should not call the current value archive identity.

### R2-7. [MAJOR] `ARCHIVED` has two contradictory canonical representations

Lifecycle §2's canonical-representation table says `ARCHIVED` means the archive
is canonical and “no cell data exists.” The state transition happens at step 3,
before steps 4 and 5 destroy and release XFS; the ordering invariant explicitly
says two verified copies exist between steps 3 and 5. Code implementing a switch
on `VolumeState` cannot satisfy both statements. Either keep the state
`ARCHIVING` through release and enter `ARCHIVED` only when placement-free, or
make the canonical table depend on `(State, ArchiveCycleStep)` and stop claiming
that state alone identifies representation.

### R2-8. [MINOR] Account-hash preimage encoding is not exact

The account formula says `volumeID-bytes`, while current Go code decodes the UUID
to 16 binary bytes before base32 encoding. A different implementation could
hash the 36-byte lowercase UUID string and derive another account. Pin the
preimage as the 16 RFC 4122 UUID bytes followed by an unsigned big-endian u64,
and add a golden vector. The 128-bit collision policy should say that any
existing mismatched account is a safe placement refusal, not a reason to choose
another name.

### R2-9. [BLOCKER] The binary manifest is not yet a byte-level format

`pack-format.md` says the layout is explicit and little-endian, but it does not
assign widths to most header and table fields, give header/table magic values,
define offsets or alignment, choose widths for length-prefixed byte strings and
extent counts, state digest byte encoding, or provide one golden manifest. The
footer's “fixed magic” has no value. `parentIndex` is the rare field that does
have a width.

Two independent implementations cannot emit or parse the same bytes from this
document. This also prevents exact parser bounds: a verifier cannot know whether
an attacker-controlled count is u32, u64, varint, or derived from a table byte
length. Before freeze, add a field-by-field binary layout, checked arithmetic
rules, maximum table sizes, offset validation, and golden files for an empty
volume plus a tree containing sparse data, hardlinks, and non-UTF-8 names.

### R2-10. [BLOCKER] Archive/restore drops supported user xattrs

The entry table has no xattr records, and the round-trip suite does not compare
xattrs. PortableFS refuses new xattr writes, but the frozen contract still
supports reading, listing, and removing pre-existing portable `user.*`
attributes (`COMPATIBILITY.md`, “Filesystem semantics”; also
`xfs-authority-architecture.md:446-464`). A wake would silently erase data that
the mounted API exposes.

Either encode every supported xattr as a bounded raw name/value list, restore it
before serving, and include it in semantic identity, or make archive fail with a
typed refusal when any supported xattr exists. Silently omitting it is not an
additive evolution of the frozen filesystem surface.

### R2-11. [MAJOR] One priority-boundary offset cannot address multiple packs

The manifest header contains one `priority-boundary offset`, while an archive
may have up to 1,024 packs. §“Ordering” describes a ranged GET from offset zero
to that boundary without naming a pack. If priority content crosses a pack
boundary, the value is ambiguous. Represent the boundary as `(packIndex,
packOffset)`, or record one priority length per pack and define traversal order.

### R2-12. [MAJOR] Content dedup can conflict with sparse-layout preservation

The format deduplicates “byte-identical files,” and `contentDigest` treats holes
as zeros. A sparse file and a fully allocated zero-filled file can therefore
have the same logical bytes and digest but must restore different extent maps.
Their stored slice lengths also differ. Dedup eligibility must require identical
logical chunk extent maps and stored-byte digests, not only logical file bytes;
the property suite should include allocated-zero versus hole-equivalent pairs.

## Contract conflicts that remain before freeze

Revision 2 says later implementation will amend several documents, but those
documents are current product contracts now:

- `docs/architecture.md:25-35` says one volume is one XFS project served by one
  authority and XFS is the only durable truth; its “What not to build” section
  forbids a checkpoint format and second durable store. ARCHIVED and RESTORING
  directly change those statements.
- `docs/consistency-model.md:5-22` and
  `docs/xfs-authority-architecture.md:82-96` say the mounted XFS instance is the
  sole source of truth and there is no manifest/checkpoint. Restore mode makes a
  sealed base plus map plus XFS the source of truth.
- `docs/xfs-authority-architecture.md:135-137` bars sidecars from writing the
  tree. The proposed hydrator still does not write XFS, which preserves the
  serving rule, but namespace restoration writes while the authority is absent
  and needs the promised phase-qualified amendment.
- `docs/failure-modes.md:17-31` lacks `FAILURE_CLASS_RESTORE`, and its
  `statfs` rule at lines 210-217 conflicts with lifecycle §5.
- `docs/hosted-control-plane.md:334-346` calls backup/restore an offline
  operator/provider workflow and bars remote snapshot commands. Typed archive
  phases are a legitimate new internal design, but the old scope statement is
  still in force.
- `docs/hosted-cell-deployment.md:37-67` installs four binaries and four units
  and gives the authority exactly three bind mounts. Revision 2 adds two
  binaries, two unit templates, credentials, and a hydrator socket bind.

The hosted Manager schema, signed cell plans, helper state, and HTTP APIs are
internal under `COMPATIBILITY.md`, so v2 prefixes and a one-way offline state
migration do not break a frozen public surface. The authority wire can grow
additively, but `FAILURE_CLASS_RESTORE` and any restore-specific protocol field
must follow the existing additive protobuf/feature rules; unknown canonical
request fields are still refused. None of the frozen ALPN, protocol major,
required feature strings, cache-policy names, `.portablefs/local-dirs` syntax,
`pfslocal` major, environment names, CLI commands, or release identity may be
renamed or repurposed.

## Final verdict: NOT READY TO FREEZE

Remaining blockers:

1. Authenticate helper-produced host facts and replace the two-snapshot
   membership gate with one attach-closed, process-bound quiesce proof.
2. Define planned mount teardown that produces `CleanDetach` before enrollment
   revocation, including the macOS renewal-failure path and already-fenced
   mounts.
3. Add a dead-cell release/abandonment protocol so a Manager-verified sealed
   archive can restore without the lost helper.
4. Fix fetch-free hydration ordering and specify one chunk state-machine lock
   shared by recall, drain, writes, and truncates.
5. Keep restore admission charged through convergence; require fresh usage for
   every placement and pin the sealed-allocation/headroom algorithm.
6. Make the v2 rollout gate capability-based, finish manifest/parser bounds,
   and define the exact S3 checksum capability contract.
7. Finish the binary manifest, preserve or explicitly refuse supported xattrs,
   and make multipack priority and sparse-dedup rules unambiguous.
8. Reconcile `ARCHIVED` state semantics, strengthen `RootDigest`, complete the
   destroy-proof identity, and update every normative document the specs claim
   to amend in the same freeze change.
