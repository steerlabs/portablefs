# Failure modes

Protocol 7 scopes coherence failures to permissions, identities, or handles.
The mount survives subscription recovery, recall budget loss, and Authority
epoch replacement. Authentication, exact replay, and storage invariants still
fail closed. The full contract and accepted residuals are in
[portable-coherence.md](./portable-coherence.md).

## Failure scopes

| Scope | Examples | Result |
| --- | --- | --- |
| Request | validation, permission, ordinary XFS errno | request fails; session continues |
| Delegated identity | missed recall budget, stale-generation flush, delayed quota failure | loss advances; affected handles report errors; root barrier fails |
| Subscription | missing change delivery or expired horizon | all cache permission withdrawn; cold resubscription after invalidation |
| Session | authentication failure, replay mismatch, unprovable assigned mutation outcome | fail closed without inventing a successful result |
| Volume epoch | Authority death, fatal XFS I/O or topology error | old capabilities, locks, and handles die; new handles require cold reattachment |
| Restore | archive-store outage, absent hydrator, digest failure | content reads fail with FAILURE_CLASS_RESTORE; epoch and sessions remain alive |
| Frontend | unsupported FUSE level or operation outside profile | refuse explicitly; no silent downgrade |

Failure never converts an already-applied mutation into a new retry. Responses
retain the STORAGE, COHERENCE, ROUTES, RESTORE, and INTERNAL failure classes;
errno alone does not identify scope.

## Authority, storage, and replay

XFS I/O failure or violation of the pinned volume root fences the volume epoch.
The Authority never redirects to another tree or reconstructs a namespace from
a client journal. READY uses XFS; RESTORING also loads its verified sealed base
and durable hydration map. These are state-selected representations, not
competing writable truths.

Authority restart creates a new epoch. Every old handle stays EIO, including
root-directory barrier handles, and volatile locks are lost. The mount
reattaches with its configured attach grant, subscribes cold, and restarts
session-bound reauthorization; new opens can work if that grant is still valid.
Replacement-grant acquisition is not wired into this recovery path. An expired
or refused grant keeps recovery cold and retrying.
Old Linux membership is fenced through its subscription horizon. Unproven
membership still blocks route/archive transitions until absence is established;
old Mac membership requires its compatibility-cache fence.

Same-epoch exact replay returns the retained result without re-execution.
Reusing an operation identity with a different canonical body or skipping its
sequence fences the session. A reply lost across Authority death may be
UNCERTAIN; it is not resubmitted in the new epoch. The application inspects
current state and restarts the affected run.

## Recall, partition, and cache withdrawal

A recall stops admissions under the retiring delegation, drains in-flight
operations, flushes its cut, and acknowledges the exact application ticket.
The budget is five seconds. Missing it drops the delegation's retained data,
advances loss, and produces EIO on affected handles and their run barrier.
A healthy mount remains available for independent identities.

A partition prevents subscription renewal. The client stops cache admission
ahead of its conservatively anchored horizon, invalidates, and resubscribes
cold on recovery. The Authority waits for acknowledgment or the old horizon
before proceeding. Renewal cannot revive a fenced incarnation. CONTROL polls,
renewal, and acknowledgments have independent lanes; assigned mutation replay
still preserves exact outcomes across a same-epoch reconnect.

Cache-installing replies drain by exact identity/name coordinates. Shared
kernel name validity is zero; inode notifications withdraw data and attributes.
Failed invalidation stales the affected inode, not the whole mount. A stopped
daemon remains the explicit resident-page residual: an existing descriptor or
private mapping may read previously resident pages until the daemon resumes
and invalidates. Stock FUSE offers no userspace mechanism to fence those reads.
Reverse d_path/getcwd rendering of retained dentries is outside the contract.

## Process failure and completion

A dead mount daemon loses its volatile accepted tail and the kernel eventually
aborts its FUSE connection. A missed delegation budget can lose data that was
accepted but not durable. Neither fsync-completed data nor namespace operations
already applied at the Authority become an offline replay log.

A clean unmount drains accepted writes to a durability barrier before stopping
the buffer and detaching. Force unmount makes no promise for non-durable entries.
A run opens the mount root before starting and fsyncs that exact handle before
reporting success, including sandbox exit and detach. Loss since that open
fails the barrier. New handles after epoch recovery start a new observation;
they cannot make an old run's failed barrier succeed.

## Capacity, quota, and routing

XFS project-quota exhaustion returns the authoritative storage errno at apply.
A buffered write can discover ENOSPC/EDQUOT later, on flush; affected handles
and the run barrier report the loss. Buffer caps block admission, and pending
close cleanup throttles new handles before the shipping open table fills. No
case redirects data to a different filesystem.

When block and inode hard limits are installed, `statfs` on the project
directory reports the project's limits and remaining capacity. Hosted
tiered-storage admission and `df` depend on that projection; a project without
hard limits retains cell-wide XFS capacity.

Hosted placement separates physical exhaustion from unavailable evidence. If
a durably eligible cell can hold the reservation but every such cell lacks a
fresh authenticated heartbeat or full usage observation, create/wake fails
unchanged with `ErrCellUnavailable` (HTTP 503). If no eligible cell can fit the
reservation after pending charges, quota-charged stale placements, reserve,
and wake headroom, it fails with `ErrCapacity` (HTTP 409). Neither refusal
releases an existing placement's durable pending charge or allocator identity.

A `.portablefs/local-dirs` revision mismatch refuses Attach and returns the
authority's current declaration for an explicit same-capability retry. A live
route change fences existing sessions because their local/shared classification
is no longer the volume's declared one.

## Restore interruption and corruption

`RESTORE_BLOCKED` covers an unreachable archive store, invalid credentials, or
an absent hydrator. Every content read fails with definite `EIO` and
`FAILURE_CLASS_RESTORE`, including reads of hydrated content; namespace and
attribute operations continue. Mounts stay alive, drain retries with backoff,
and the state clears when verified fetches succeed again.

`RESTORE_CORRUPT` covers a fetched chunk that fails digest verification. Content
reads stop uniformly, affected paths remain enumerable from the sealed
manifest, and unverified bytes are never served. Repair must re-establish a
Manager-verified sealed representation. Restore errors never enter the fatal
storage set and never end the authority epoch.

## Platform refusal

A Linux kernel below FUSE protocol 7.31 is refused during FUSE INIT. INIT is the
first point at which userspace learns the kernel protocol level, so the paired
authority session already exists; the failure path proves that no usable mount
was installed and cleanly detaches it. A kernel at or above the floor is not
required to advertise any private PortableFS capability; none exists.

O_APPEND placement is Authority-resolved at true EOF. Stock FUSE does not
forward per-call RWF_APPEND/RWF_NOAPPEND; their disclosed deviations are in the
consistency model, not silently inferred from an offset.

macOS 26 and 27 mount through the explicit `FSKIT_SYNC_REPAIR` profile. Current
FSKit cannot prove name/attribute cache withdrawal, per-reply metadata installation
control, exact append intent, or distributed locks, so those edges are declared
best-effort. The authority still orders its PREPARE/COMPLETE repair around the
same XFS mutation and fences a session that misses that repair deadline.

Windows has no production frontend and is refused by its primitive gate.

## Verification

- `scripts/xfs-fuse-integration.sh` runs the privileged XFS and real stock-FUSE
  integration suite and verifies every required test reported PASS.
- `scripts/coherence-matrix-linux.sh` drives two independent stock-kernel
  mount processes through ordinary syscalls and runs falsifiability controls.
- `scripts/run-powerloss.sh` distinguishes process death from device-level
  durability cuts.
- `scripts/verify-local.sh` runs portable compile, unit, race, workflow-policy,
  and active-contract scans; `--full` also runs the two suites above.

The exact subscription/delegation algorithm and remaining qualification are in
[portable-coherence.md](./portable-coherence.md).
