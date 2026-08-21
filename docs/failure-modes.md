# Failure modes

PortableFS protocol 6 is fail-closed except for two explicitly disclosed
stock-FUSE clean-data residuals. This document states what fails, what scope is
fenced, and what an application can observe.

The canonical storage depends on `(State, ArchiveCycleStep)`: XFS for READY,
the sealed archive for ARCHIVED, and sealed base plus monotone hydration map
plus XFS for RESTORING. A serving volume still has one authority epoch. Failure
scope never turns these representations into competing writable truths.

## Failure scopes

| Scope | Examples | Result |
| --- | --- | --- |
| Request | validation, permission, quota, ordinary XFS errno | that request fails; session continues |
| Session | protocol violation, replay mismatch, failed recall, lost lease control | that mount is fenced; other mounts continue |
| Volume epoch | authority death, XFS I/O error, storage topology violation | all sessions end; restart creates a new epoch |
| Restore | archive-store outage, absent hydrator, or digest failure | content reads fail uniformly with `FAILURE_CLASS_RESTORE`; the epoch and sessions remain alive |
| Host frontend profile | unsupported FUSE level or a request outside the declared profile | Linux refuses during INIT and cleanly releases the pre-mount session; FSKit rejects Linux lease operations and Linux rejects FSKit repair operations |

Fencing never converts an already-applied mutation into a retry. If the
authority cannot establish the exact result, it reports uncertainty or ends the
affected scope.

Responses distinguish `FAILURE_CLASS_STORAGE`, `FAILURE_CLASS_COHERENCE`,
`FAILURE_CLASS_ROUTES`, `FAILURE_CLASS_RESTORE`, and
`FAILURE_CLASS_INTERNAL`; errno alone is not the failure scope.

## Authority and storage failure

An XFS I/O failure or a violation of the pinned volume root makes the store
untrustworthy. The authority fences the volume epoch and stops accepting
filesystem operations. It does not redirect to another directory, rebuild from
a PortableFS journal, or keep a partial namespace alive.

Authority death ends every live session and loses volatile locks and leases. A
restarted authority uses a new epoch and holds a grace period for the maximum
conservative lease-expiry bound before admitting a conflicting mutation. This
prevents a new epoch from racing a lease the restarted process cannot remember.
Persisted lease recovery is not claimed.

A RESTORING replacement additionally loads the durable hydration map and sealed
base identity. Those records are that state's canonical representation, not a
mutation replay log.

## Lost mutation reply

Inside one live epoch, exact replay of a daemon operation identity returns the
retained result without re-execution. Reusing an identity for a different
canonical body or skipping its required sequence fences the session.

There is no atomic transaction spanning an arbitrary XFS syscall and a durable
PortableFS replay record. If the authority may have applied a mutation but its
reply is lost across authority death, the result is `UNCERTAIN`. The client does
not resubmit it in the new epoch. The application inspects current state.

## Lease recall and fencing

A conflicting mutation closes grant admission, recalls peer N/A/D/E leases,
applies to XFS, delivers exact post-state, and waits for discharge before the
source response. A healthy peer purges all state covered by the recalled lease.
Whole-file D leases recall only to none in v1; range-successor continuity is not
implemented.

If a peer does not discharge within the recall budget, the authority fences its
session. The mutation may proceed only after the old conservative expiry bound
has elapsed. This can delay one mutation; it does not fence the volume.

On Linux, the daemon uses an ordered installing lane and a zero-validity
metadata lane. An already-admitted buffered READ drains before REVOKE
acknowledgment; a new READ at a closed cut returns `EAGAIN` without waiting
behind invalidation. The mutating mount uses an exact source obligation: A/D/E
and daemon N purge before reply; kernel name validity is always zero, so source
completion does not depend on a post-write namespace notification.

Zero name validity governs forward pathname resolution, not reverse rendering
of retained dentries. `getcwd`, `/proc/*/fd`, and other `d_path` users can show
an older path after a remote rename because stock Linux performs no
revalidation there; that operation class is outside the protocol-6 namespace
contract.

An invalidation error that stock FUSE reports fails the discharge and fences the
mount. Stock FUSE does not report the result of data-page invalidation; that
specific boundary is described below.

## Mount process and machine failure

If the daemon dies, the kernel aborts the FUSE connection and no new request is
served. The authority fences the session and reclaims its leases after the
expiry bound. A machine loss has the same authority-side result.

A clean unmount closes request admission, drains operations, returns leases,
closes the FUSE connection, and sends authenticated detach. Force unmount makes
no durability promise beyond operations that already returned; there is no
client write-back tail to replay.

## The two accepted clean-data residuals

### Wedged daemon

Kernel-held clean pages have no independent lease timer. If a daemon is alive
but cannot run—for example, stopped by SIGSTOP—it cannot purge those pages at
lease expiry. After the authority fences that mount and a peer mutates the
file, a process on the wedged mount can read stale cached bytes until the daemon
resumes or dies.

The trigger requires all of: a wedged-not-dead daemon, fencing, a peer mutation,
and a cached read-only page. It does not affect metadata, accepted writes, or
durability. Process supervision bounds the condition operationally but does not
remove it from the contract.

### Unproved data-cache withdrawal

The client ends cache validity and starts D-page withdrawal five seconds before
the authority horizon. Renewal, withdrawal, and the terminal watchdog are
independent, so a blocked renewal cannot postpone that work. Stock Linux FUSE
nevertheless discards `invalidate_inode_pages2_range`'s `EBUSY` result, and a
notification can also remain blocked through the withdrawal interval. The
watchdog terminalizes and aborts the mount before the authority proceeds.

Channel abort prevents new FUSE work but does not itself invalidate resident
folios. A read-only file descriptor or private mapping that already references
an old clean page can therefore keep observing it after a peer mutation,
potentially for the reference's lifetime. No new open, cache miss, daemon
answer, metadata answer, accepted write, or durability result is authorized.
A later successful purge or destruction of the reference removes the
exposure. Removing the exception requires a bounded, result-bearing kernel
invalidation or cache-generation primitive; surfacing `EBUSY` alone does not
solve a notification that never completes.

## Partition and expiry

A partitioned daemon cannot renew leases. Daemon cache hits check the earlier
request-start-anchored cache deadline and miss then; kernel entry validity is
zero and attribute validity expires no later than that deadline. The daemon
starts purging D-covered pages five seconds before the authority horizon. If it
cannot prove withdrawal, the independent watchdog terminalizes the mount before
that horizon. New operations degrade to errors; preexisting cached data
references remain subject to the explicit exception above.

Loss of the CONTROL transport closes lease grant and mutation admission. It is
not replaced by polling DATA traffic or a reduced-coherence mode. Reconnection
is valid only while session, epoch, transport generation, and leases remain
exact.

## Capacity, quota, and routing

XFS project-quota exhaustion returns the authoritative storage errno. In-memory
bounds reject new work before unbounded allocation. Neither case redirects data
to a different filesystem.

When block and inode hard limits are installed, `statfs` on the project
directory reports the project's limits and remaining capacity. Hosted
tiered-storage admission and `df` depend on that projection; a project without
hard limits retains cell-wide XFS capacity.

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

The protocol-6 writable Linux profile is not production-ready: PortableFS can
refuse `O_APPEND`, but stock FUSE does not forward `RWF_APPEND`, so the daemon
cannot detect or refuse that append request. This is a correctness blocker, not
a runtime fallback condition.

macOS 26 and 27 mount through the explicit `FSKIT_SYNC_REPAIR` profile. Current
FSKit cannot prove N/A/E lease discharge, per-reply metadata installation
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

The exact lease algorithm and open upstream work are in
[portable-coherence.md](./portable-coherence.md).
