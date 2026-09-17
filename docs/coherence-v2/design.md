PortableFS Coherence v2

  Design proposal · PortableFS · revision 3
  # PortableFS Coherence v2

  The Authority owns the namespace. Mounts own the files they are writing, through identity-scoped write delegations with daemon-side write-back. Readers cache under one volume-wide subscription whose permission is withdrawn before any delegation is granted. One writer or five, one contract.

  2026-09-16Status: proposal for review, revision 3Red-teamed three times by Codex (gpt-6-astra, high), once by a second reviewer, and checked twice against the Authority and FUSE client sourceCompanion to the PortableFS Audit

**What changed since revision 1.** Revision 1 gave mounts local authority over directory subtrees, so creates and renames ran locally and were journaled. Three reviews produced counterexamples that each needed a new rule: a peer removing a directory whose local children are unflushed, two machines moving directories into each other, a rename over a file another machine is writing, the parent pointer of a moved directory, pre-assigned identities that the storage layer cannot provide. Each is closable. Together they are a second distributed filesystem hidden inside the first. So the namespace goes back to the Authority, where the sequencer already orders it correctly, and delegation is scoped to files. That drops most of revision 1's obligations and keeps the two things that matter: writes never wait on the network, and reads are served from cache.

**What changed in revision 3.** A final adversarial pass found four more holes and three assumptions the code contradicts. A peer holding an ordinary buffered read handle could re-cache a delegated file, so a delegation now drops to write-through while any peer holds a cache-capable handle, which is the SMB lease-break rule. Stock FUSE does not deliver `syncfs` to the daemon, so the completion barrier is `fsync` on a directory handle opened at run start, which the kernel always delivers. There is no open-by-identity path, so an Authority restart stales every open handle and fails the runs holding them, rather than pretending to recover. Quota reservation, immutable listing snapshots, and transparent epoch recovery were removed as machinery that bought less than it cost. Known residuals and the proofs required before implementation are now listed explicitly.

**What it costs.** One round trip per namespace operation per process, in parallel across processes, instead of three serialized round trips per file behind a mount-wide gate. Directory delegation, which would make namespace operations local too, is specified as a later extension with its obligations listed, to be built only if measurement after this foundation says the namespace round trip is still the bottleneck.

  - **0** Round trips on the foreground path for `write`, `ftruncate`, `utime`, and `fsync`-free `close` of an uncontended delegated file

  - **1** Round trip per namespace operation, ordered by the Authority's sequencer, no client-side gate; today 1 to 3 serialized per file

  - **2** Primitives: change subscription, file write delegation. Replaces four lease families, the gate, and the watchdog abort

  - **1** Barrier per run: `opendir` the mount root at start, `fsync` that handle at the end. `EIO` means the run lost data

## The decision

Three designs were on the table. Whole-volume ownership, the Archil shape, refuses two machines writing one workspace. Subtree or directory delegation with local namespace authority gets the best numbers and the longest list of correctness obligations. Authority-owned namespace with file delegations is the smallest design that gives concurrent writers on different files, correct competition for the same file, local-speed data, and cached reads. It is the NFSv4 delegation and SMB lease shape, which is the shape every production network filesystem with write caching has converged on. It is chosen here for the same reason the reviewers gave: the obligations it removes are the ones that generate weird bugs.

## The contract

  - **Namespace operations execute at the Authority.** create, mkdir, unlink, rmdir, rename, link, symlink, and mknod are one synchronous request each. The Authority's mutation sequencer orders them by identity and (parent, name), so independent operations from different processes and different mounts run concurrently. The client keeps no gate.

  - **Data and file attributes execute locally under a write delegation.** A mount holding a delegation on file identity F buffers writes, truncates, and attribute changes to F in the daemon and returns immediately. The buffer is flushed on a timer, at a cap, on `fsync`, at the run barrier, on recall, on unmount, and before any namespace operation that names F.

  - **A subscriber caches an item only while nobody holds a delegation on it.** Granting a delegation on F first withdraws every other subscriber's cache permission for F, and the grant activates when each has acked or its horizon has passed. A committed namespace operation delivers its change entries to subscribers the same way before it is acknowledged.

  - **Peer access to a delegated file breaks the delegation before it is answered.** Any server-side operation that consumes F's data, size, or attributes (READ, GETATTR, LOOKUP and READDIR that return attributes, FSYNC, the source side of COPY_FILE_RANGE) first makes the holder flush F to an accepted-sequence cut, then is answered. Any server-side operation that mutates F's data or size (WRITE, SETATTR size, FALLOCATE, the destination side of COPY_FILE_RANGE) recalls the delegation first. While any other session holds a cache-capable handle on F, the delegation is held in write-through form: writes still go through the daemon but are sent immediately, and each commit invalidates the peers through change delivery. Handles a peer opens on an already-delegated file are direct-IO and do not downgrade it.

_Figure: Namespace operations are one ordered round trip. Data under a delegation is local until a peer looks, a timer fires, or a namespace operation names the file. Cache permission and delegation never coexist on one identity._

## Primitives

### Change subscription

  - One per mounted participant, volume-wide. TTL 10 s on the Authority clock, renewed every 3 s. At its horizon without renewal the client drops every cached item and invalidates the kernel's copies. The horizon is the fence for a partitioned reader.

  - Each committed namespace operation, and each delegation grant or release, appends an ordered change entry: identities, (parent, name) pairs, and the volume version. Entries stream to every other subscriber over the CONTROL connection in batches, and a subscriber acks cumulatively by stream position. An ack of position N means every entry through N has been fully withdrawn on that client: kernel pages, attributes and names invalidated through reverse notify, and every pending reply that could install cache state for those items drained, within the same subscription incarnation. The Authority waits for that ack, or the subscriber's horizon, before acknowledging the operation or activating the grant. At the horizon the subscriber's session is fenced: nothing it sends is honoured until it resubscribes cold, which it may do only after invalidating everything.

  - Subscribing returns a version watermark and the set of currently delegated identities, so a fresh subscriber opens delegated files direct-IO from its first lookup. The first cacheable read is at or after the watermark. Read replies carry the version at which they were served; the client's publication step discards any reply older than the last withdrawal or change for that item, so a delayed reply cannot repopulate a cache after its ack. This is the existing read-publication drain, kept.

  - Under a subscription the client caches attributes, name bindings, negative lookups, directory listings, and data pages. Listing replies already carry every entry's attributes on the wire; under a subscription they are cacheable as they arrive, because a later change to any entry invalidates it. The admission-ordering problem the audit found for per-entry leases does not exist here.

### File write delegation

  - Scope is one file identity: its data, size, and attributes. Requested inside CREATE and inside OPEN-for-write, so it never costs a separate round trip on the common path; the Authority reserves the delegation before it exposes the new binding, so no peer can cache the identity between the create and the grant. After a recall, the next write on an already-open handle re-requests it, one round trip. Granted when no other participant holds a delegation on it, after every other subscriber's cache permission for it has been withdrawn. Released in batches once the mount has closed its last handle and flushed, so the Authority's 65,536-per-session grant table is never the limit during an install.

  - Under a delegation the daemon buffers writes, truncates, and attribute changes and returns immediately. File handles stay `FOPEN_DIRECT_IO`, so every `write(2)` reaches the daemon in one context switch and is admitted or refused there. The kernel write-back cache stays off, which is what makes a recall enforceable: the daemon stops admitting, and there is no kernel-resident dirty state to chase.

  - Flush triggers: a 1 s timer, the cap (64 MiB dirty or 10,000 entries per mount, after which writes block until the flush advances), `fsync` of the file, the directory-handle barrier, a break for read, a recall, unmount, and any namespace operation that names the identity. Flushed writes go through the existing 1 MiB write RPC, pipelined across the RPC lane, in per-file order.

  - Each entry moves through four states: accepted, applied, visible, durable. The daemon keeps an entry until it is durable, which the Authority signals with its existing coalesced fsync group. A write on a handle opened with `O_SYNC` or `O_DSYNC` returns only when its entry is durable. An epoch change with any non-durable entry outstanding advances the mount's loss sequence.

  - Recall is two-phase: withdraw, stop admitting under the retiring generation, drain in-flight writes, flush, ack with the applied sequence. Budget 5 s. A missed budget drops the delegation and its buffer, advances the loss sequence, and returns `EIO` on the affected handles' next write, close, or fsync. The mount stays up.

  - Flushes carry (delegation id, generation). A flush from a stale generation is rejected whole and advances the sender's loss sequence.

  - Reads on the holder's own mount see its buffer: the daemon overlays dirty ranges on fetched data. Read handles on a locally delegated file may still use the kernel page cache, because every accepted local write to that file invalidates the written range in the kernel when a cacheable read handle is open. So a compiler can still `mmap` a file the agent just wrote. Today there is no daemon-side data buffer or overlay; this is the largest single piece of new client code.

## Walkthroughs

### One writer installs 40,000 files

Each file is one create round trip that returns the delegation with it, then buffered writes and attribute changes at local speed. The round trip per file pipelines across the installer's worker threads and across processes, up to the 94 concurrent slots the client lane allows once the gate is gone; creates in the same directory serialize on that directory's attributes at the Authority, creates in different directories do not. Data flushes on the timer in the background. Compared with today: three round trips per file, each serialized against every other mutation on the mount. The create round trip is what remains, and it is what directory delegation would remove.

### A user opens a file the agent is writing

The user's mount asks the Authority for the file. The Authority sees A's delegation, sends A a flush for that identity to an accepted-sequence cut, A flushes, and the Authority answers. The reader's handle was opened after the delegation existed, so it is direct-IO and caches nothing; A keeps buffering. If instead the reader had held an ordinary cached handle from before A started writing, A's delegation would have dropped to write-through for as long as that handle stays open, and every A commit would invalidate the reader through change delivery. If the reader writes, the delegation is recalled from A and granted to the reader. The Files sidecar reads through the gateway with no kernel cache, so it never downgrades anyone.

### Git's lock protocol across two machines

Machine A commits: `.git/index.lock` is created with O_EXCL at the Authority, written under a delegation, and renamed over `.git/index`, and the rename flushes the lock file's data first, then executes at the Authority. Machine B runs `git status`: its lookup of `.git/index` is a name binding, which the rename's change delivery already invalidated, so B fetches the new binding and, because A's delegation may still cover the identity, reads it after a break for read. If B instead takes the lock, its O_EXCL create is ordered by the sequencer against A's, and exactly one wins. Nothing here depends on timers.

### Two writers, same directory

A and B both create files under `pkg/`. Each create is a sequencer-ordered round trip; they interleave without conflict because they touch different (parent, name) pairs. Each side gets delegations on the files it opened for writing. The directory listing on each side is invalidated by the other's creates and refetched lazily. There is no directory lease to contend for.

### Two writers, same file

A holds the delegation and is writing. B writes. The Authority recalls A's delegation, A flushes and acks, B is granted it. If both keep writing, the delegation moves on each switch, and each switch costs A or B a flush. Bytes from both sides land in the order the flushes were applied. No filesystem merges concurrent edits to one file; this one keeps every acknowledged byte and never lets two machines' buffers diverge silently.

### Runner failover

The new runner mounts, subscribes, and starts creating and writing. Its first write to a file the old runner delegated triggers a recall. If the old runner is alive, it flushes. If it is dead, the recall times out at 5 s and the delegation is dropped; up to one flush interval of the old runner's un-fsynced data is gone, which is the local-disk contract. Its namespace operations were all already applied, because the namespace is never buffered.

## Failure matrix

| Event | What is lost | What processes see | Mount |
|---|---|---|---|
| Writer host crash | Buffered data accepted after the last completed flush; typically under a second, at most one cap. Nothing fsync'd, nothing written with O_SYNC, and no namespace operation | Same as a local disk after a power cut | Gone with the host |
| Writer partitioned from Authority | Buffers under delegations that expire during the partition | Writes block at the cap, then EIO on affected handles; loss sequence advances; namespace operations fail with EIO immediately since they need the Authority | Stays up; reconnects and resubscribes cold |
| Writer misses a recall budget | That file's buffer | EIO on next write, close, or fsync of that file; loss sequence advances | Stays up |
| Reader misses a change delivery or its horizon | Its cache | Nothing after the daemon invalidates; next reads miss and refetch. Residual: a process reading a page already resident through a descriptor it holds, while the daemon itself is stalled, can see pre-withdrawal bytes until the daemon resumes and invalidates. This is inherent to stock FUSE and is the same residual the current code documents | Stays up, resubscribes after invalidating everything |
| Reader partitioned | Nothing on the Authority. Writers' operations that must invalidate it wait at most the reader's horizon, 10 s | Reader's processes see cached data until the horizon, then errors until reconnect | Stays up |
| Authority crash (new epoch) | Every mount's non-durable buffer; every delegation, subscription, lock, and open server handle | Every handle open at the time is permanently stale with EIO, because item capabilities are epoch-local and there is no open-by-identity. The loss sequence advances. New opens work after re-attach. Runs holding files at the time fail at their barrier and are restarted by the product | Stays up after re-attach; today this is a forced remount |
| Authority planned restart | Nothing: the control plane quiesce recalls every delegation, which flushes every buffer, and waits for durability | A pause; handles survive because the session is resumed within the same epoch | Stays up |
| Stale-generation flush | That flush, whole | EIO on affected handles; loss sequence advances | Stays up |
| Quota exhausted | The buffered entries the Authority rejects with EDQUOT at flush | ENOSPC on the affected handles' next write, close, or fsync, and at the run barrier. The Authority never reads quota usage today and a reservation scheme would be new state on both sides; delayed reporting is the NFS contract and is accepted here | Stays up |
| Unmount with a dirty buffer and unreachable Authority | The buffer, after waiting to the delegation horizon | Unmount completes after the horizon; loss logged | Gone by request |

## Fixed rules

Each closes a hole a reviewer demonstrated. Each is one rule that always applies.

- **F1 Application locks are always Authority-mediated.** `flock` and `fcntl` go to the Authority regardless of delegations. They die with the epoch along with every other open handle; nothing is reclaimed. Half the RPC lane stays reserved for blocking lock waits.

- **F2 No shared writable mmap.** Refused at `mmap`, as today. Private and read-only mappings work on cacheable handles, and are invalidated through reverse notify, which unmaps them. Runner kernels are not pinned anywhere in OpenSteer, so `FUSE_DIRECT_IO_ALLOW_MMAP` cannot be assumed, and the design does not depend on it.

- **F3 Listings continue from the Authority's cookie.** Directory pages are fetched by the Authority's cookie, which is XFS's stable offset, and cached under the subscription. A change to the directory invalidates the cached listing; a handle mid-iteration continues from its cookie and sees the POSIX-permitted unspecified result for entries added or removed during the walk, never `ESTALE`. Revision 2's immutable per-handle snapshot was removed as more than readdir promises.

- **F4 A namespace operation that names a delegated file flushes it first.** rename, link, and unlink of an identity with dirty data flush that identity before the request is sent. This is ext4's rename-flush behaviour made explicit, and it is what makes write-then-rename safe without flushing on every close.

- **F5 Flush order follows program order per file, and every barrier takes a cut.** `fsync(F)` flushes F's accepted entries and waits for their durability. A barrier on the mount snapshots every accepted entry at call time, waits for application and durability of that cut, and lets later operations proceed. Neither overtakes an accepted entry.

- **F6 The run barrier is `fsync` on a directory handle.** Stock FUSE does not deliver `syncfs` to the daemon on ordinary mounts, only on virtiofs, so `syncfs` can return 0 without the daemon ever seeing it. `FUSE_OPENDIR` and `FUSE_FSYNCDIR` are always delivered. The daemon records the mount's loss sequence when a directory handle on the mount root is opened; `fsync` on that handle performs the mount-wide cut and returns `EIO` if the loss sequence advanced since the open. No new control surface, no sticky flag, no remount, and concurrent runs on one mount each observe only losses during their own lifetime. Revision 2's per-mount sticky flag was removed.

- **F7 Completion contract.** The runner opens the mount root directory before a run's first operation, and at run completion, sandbox exit, and detach it calls `fsync` on that handle and fails the step on `EIO`. Archive and planned Authority restart perform the same barrier from the control plane. A run is successful only after its barrier returns 0. Today OpenSteer gets this implicitly from write-through; with write-back it has to be a call.

- **F8 Admission stops before draining.** On a recall or cap, the daemon stops accepting entries under the retiring generation, drains in-flight ones, then flushes. Writes arriving during the drain block; they neither fail nor slip into the old generation.

- **F9 The Authority never holds a commit lock while waiting on a peer.** Change delivery, recall, and flush application run on separate lanes; a recall ack names the sequence it drained to. Requests queue FIFO among conflicting identities only; disjoint requests proceed.

- **F10 Withdrawal is proven, not assumed.** A subscriber acks a stream position only after reverse notify has returned for every item through that position and every pending cache-installing reply for those items has drained. The daemon retries a notify that fails transiently within the budget. Stock FUSE discards the kernel's final page-invalidation result, so a returned notify is the strongest proof userspace can obtain; the F10 kernel test must show that with write-back off and no private page data, `invalidate_inode_pages2_range` removes every page, mapped ones included, before `notify_inval_inode` returns. The residual beyond that is the stalled-daemon case in the failure matrix, and it is stated there rather than hidden.

- **F11 macOS keeps the compatibility writer lease, for every Mac mount.** FSKit on the shipping SDK cannot invalidate names or attributes, and the SDK 27 adapter in the repo covers data only. A read-only Mac mount caches negative lookups it can never revoke, so any attached Mac mount, not only one with write intent, excludes other writers exactly as today. Lifting that is a platform project with its own proof.

- **F12 Cache-installing replies drain per identity, not mount-wide.** A delayed reply to the holder's own SETATTR can install old attributes after a recall and a peer's change. The current source-publication machinery already keys this per identity; the design keeps that keyed barrier and deletes only the two mount-wide predicates that serialize unrelated mutations.

## What it buys, and what it does not

| Workload | Today | This design | Remaining gap to local disk |
|---|---|---|---|
| Write and close one file (open exists) | 1 round trip per write(2), serialized mount-wide | 0 round trips; flushed in the background | None on the foreground path |
| Create 40,000 files, one process | 3 round trips each, serialized | 1 round trip each (the create returns the delegation), pipelined only as far as the process is concurrent | The create round trip. Sequential creates in one process are bounded by RTT |
| Create 40,000 files, 8 workers | Same as one process: the gate serializes | Round trips overlap across workers; throughput bounded by Authority ops per second | Smaller by the worker count |
| Cold git status, 20,000 files | Two round trips per entry | One listing round trip per page; entries cached with their attributes | Near none |
| Warm git status | Cached under leases with 20 s TTL churn | Cached until changed | None |
| Peer reading while owner writes | Four control round trips per recall, every write | One flush per peer read of a dirty file | Inherent |

The remaining gap is the namespace round trip per process. Two levers close it: reduce the round trip by placing Authorities and runners in the same zone, which the audit already recommended and which needs a measurement, and directory delegation, below. Measure before choosing.

## Directory delegation, specified later

A delegation on a directory would let its holder create, remove, and rename entries locally and journal them. That is what would make an install or checkout run at local speed in a single process. It is deliberately not in the foundation because the reviews showed it carries these obligations, each of which is a rule with its own failure modes:

  - Local objects need identities before the Authority has assigned one, and PortableFS identity is the XFS export handle, derived after creation. A daemon-side identity namespace with remapping at flush, stable within a mount, and a rule for hard-link aliases discovered after flush.

  - Removing or renaming a directory whose delegation another mount holds must recall it and flush its local children before checking emptiness, or the peer's accepted creates target a removed directory.

  - Concurrent local directory moves on two mounts can form a cycle that no later Authority check can reject without breaking one already-acknowledged operation. Directory moves would have to stay synchronous.

  - A moved directory's parent pointer and attributes belong to someone; rename over a file another mount holds must pin that identity for the holder's open handle.

  - Grant scope needs an allocation policy that converges instead of oscillating, with queued requests counted as conflicts and explicit identity exceptions inside a directory scope.

If, after the foundation ships and the latency work is done, a single-process install is still bounded by create round trips, this extension gets its own document with those obligations resolved one by one and a fault test for each. Not before.

## Known residuals and required proofs

Three things this design does not make perfect, stated so nobody discovers them in production, and two things that must be demonstrated before implementation starts.

  - **Stalled daemon, resident pages.** If a reader's daemon stops responding past its horizon, a process on that mount holding an open descriptor or a private mapping can read pages that were resident before the withdrawal, until the daemon resumes and invalidates. Stock FUSE offers no way for userspace to fence this. The current code has the same residual and documents it. The Authority proceeds at the horizon so a healthy writer is not held hostage by a dead reader.

  - **Delayed `ENOSPC`.** A write accepted into the buffer can fail with `EDQUOT` at flush; the process learns at its next write, close, or fsync on that file, or at the run barrier. This is the NFS contract. A reservation scheme would need quota usage the Authority does not read today.

  - **Contended files run at today's speed.** A file that a peer holds a cached handle on, or writes concurrently, is write-through with invalidation per commit. That is correct and it is what the current system does for every file.

  - **Proof 1, kernel invalidation.** On the pinned runner kernel, with kernel write-back off, show that `notify_inval_inode` returns only after every page of the range, including pages under a private mapping, has left the page cache, and that a concurrent `read(2)` and a concurrent page fault after return both go to the daemon. Without this, F10 is an assumption.

  - **Proof 2, barrier delivery.** On the same kernel, show that `fsync` on a directory handle reaches the daemon as `FUSE_FSYNCDIR` with the handle it was opened with, and that `syncfs` does not reach it, so nobody builds on `syncfs` by mistake.

## What changes

### Authority

| Capability | Today | Change |
|---|---|---|
| Namespace execution and ordering | exists per-op handlers, sequencer on identity and (parent, name), atomic multi-key grant, FIFO | None. This is the core the design keeps. |
| Monotonic volume version | exists | None |
| Epoch, session generation, grant and revoke epochs | exists | Add a delegation id; carry (id, generation) on flushed writes |
| Per-session replay slots | exists | Sufficient. Flushes are same-epoch by design; an epoch change advances the loss sequence if anything non-durable was outstanding. |
| Coalesced fsync and the syncfs barrier RPC | exists | Return a durable sequence so the client can retire entries; the daemon calls the barrier RPC from FUSE_FSYNCDIR on the root, never from FUSE_SYNCFS |
| Recall delivery over CONTROL long-poll, two-phase ack | partial one pending slot per holder, REVOKE and COMPLETE phases, so two round trips per event, serialized per holder | Replace with an ordered change stream: batched entries, cumulative acks by position. Keep two-phase only for delegation recall. |
| Change subscription and change entries | missing | New. One per participant; entries per committed namespace op and per delegation event; ack-or-horizon before acknowledgment. |
| File write delegation with cache withdrawal | partial LEASE_RIGHT_DATA_EXCLUSIVE exists and is grantable; nothing withdraws peers' cache rights first; the Authority does not know which sessions hold cache-capable handles | Extend: reserve-then-withdraw-then-grant inside CREATE and OPEN, per-identity count of cache-capable handles per session for the write-through downgrade, break on every data-consuming operation, recall on every data-mutating one. |
| Batch or transactional apply | missing | Not needed. |
| Lease persistence, grace, reclaim, open-by-identity | missing item capabilities are epoch-local and stable_identity is explicitly non-authorizing | Not built. An epoch change stales every open handle; runs restart. |
| Quota usage | missing no quotactl anywhere; the kernel returns EDQUOT at write | Not built. ENOSPC is delayed to flush and surfaced at the barrier. |
| Subtree or directory scope | missing | Not in this design. |

### Linux client

  - **New:** daemon write buffer with admission, per-file ordering, caps, generation cut, four-state tracking, retirement on durability, and the dirty-range overlay for the holder's own reads; subscription with watermark, change application, proven-withdrawal acks, and horizon enforcement; delegation table with the write-through downgrade; the loss sequence and the directory-handle barrier; stale-all-handles on epoch change.

  - **Kept:** FUSE mount profile (direct-IO write handles, explicit data cache control, no kernel write-back), the per-identity publication drain for every cache-installing reply, reverse notify on the fixed go-fuse, the transport, the blocking-lock lane, cookie-based directory paging.

  - **Deleted:** the four lease families and their tickers, the two mount-wide overlap predicates in the source publication gate, the hard-deadline watchdog that aborts the mount, and every `revoke()` whose cause is a coherence condition. Revoke remains for transport death and operator unmount.

  - **Changed:** an epoch change re-attaches and resubscribes cold with every previously open handle stale, instead of forcing a remount.

### OpenSteer

  - Open the mount root directory at run start; `fsync` that handle at run completion, sandbox exit, and detach, and fail the step on `EIO`. Restart runs whose handles were staled by an Authority epoch change.

  - Pin the runner node kernel. Nothing in the repository pins a node image or kernel version; the only floor is a seccomp profile's 4.8. The design needs 5.10 for the FUSE protocol floor already in use and nothing newer, but the F10 kernel test must run on the pinned version.

  - Remove `noLocalDirs: true`; the graft is orthogonal.

  - The Files sidecar needs nothing. Its reads are peer reads and break for read at the Authority.

## Review trail

Revision 1 went to Codex (gpt-6-astra, high) and to an Opus source check. The result went to a second reviewer, whose six findings and the second Codex round produced this revision.

| Finding | Disposition |
|---|---|
| A subscriber serves cached data while the owner writes locally, because the owner's write is not a commit and the cached read never reaches the Authority | Accepted; the central hole in revision 1. Cache permission and delegation are now mutually exclusive per identity, with withdrawal before grant. |
| Pre-assigned identity blocks are impossible: identity is the XFS export handle, derived after creation | Accepted. Local creates are gone from the foundation; the identity question moves to the directory-delegation extension. |
| "One EIO then fresh handles" is unsafe for lock holders and unlinked-but-open files across an Authority restart | Accepted as the stale-handle rule: handles with locks, non-durable data, or unopenable identities stay stale; no reclaim. |
| The 1 s loss bound and 5 s recall are unsupported; a job can close everything and succeed before a later timeout discards its outputs | Accepted. Loss is stated as "after the last completed flush", the loss sequence plus the completion barrier make every loss observable (revision 2 used a sticky flag and syncfs; revision 3 replaced both, see F6), and applied-but-not-durable entries are retained until the durability ack. |
| Disabling kernel write-back does not fence cached reads, names, or mappings; "zero mount aborts" was an unsupported promise | Accepted. F10 replaces the promise with a mechanism and a required kernel test; the claim is now "no coherence condition aborts the mount; a failed invalidation stales that inode". |
| macOS "does not subscribe" does not stop the kernel from caching; the SDK 27 adapter covers data only | Accepted. The compatibility writer lease stays. |
| Retained set can be empty, so the root ping-pongs; open-file leases overlap granted scopes; directory rename changes containment; replay slots do not order across slots; an immutable listing needs materialization; N RPCs per second is not one RPC | Accepted. Subtree scope is removed from the foundation. Listings are materialized per handle. Flush ordering is per file. The performance table states time to durable, not foreground time alone. |
| Codex round 2: rmdir against unflushed local children, concurrent directory-move cycles, rename over a held identity, parent-pointer ownership, identity exceptions, local inode namespace collisions | Accepted, and decisive. These are the obligations listed under the extension. None applies while the namespace is Authority-owned. |
| Codex round 2: a delayed read reply repopulates a cache after the withdrawal ack | Accepted. Replies carry the served version; publication discards replies older than the last withdrawal or change for that item. |
| Codex round 2: applied-but-not-durable data lost in an Authority crash with nothing to report it | Accepted. Entries are retired only on the durability ack; an epoch change with non-durable entries advances the loss sequence. |
| Codex round 2: syncfs can overtake an accepted write; per-observer errseq has no observer on FUSE_SYNCFS | Accepted in revision 2 as a sticky flag; superseded in revision 3 by the directory-handle barrier, which takes a cut and has a real observer. |
| Codex round 2: strict volume FIFO lets a partitioned holder block unrelated requests | Accepted. FIFO among conflicting identities only. |
| Codex round 2: break-for-read must include dirty kernel pages | Not applicable: kernel write-back is off, so the daemon buffer is the only dirty state. Recorded so nobody turns it on later. |
| Both reviewers: start with Authority-owned namespace and file delegations; make subtree delegation a separately justified extension | Accepted, after resisting it for one revision. The counterexamples are what changed the decision, not the recommendation. |
| Round 3: a peer's pre-existing buffered read handle re-caches a delegated file after a break, because FOPEN_DIRECT_IO belongs to the open description and cannot be retrofitted | Accepted; the most important round-3 finding. Delegations drop to write-through while any peer holds a cache-capable handle; peers' new handles on delegated files are direct-IO. This is the SMB lease-break rule. |
| Round 3: stock FUSE does not deliver syncfs to the daemon on ordinary mounts, so the completion contract could return 0 without a barrier | Accepted and verified against the kernel gating. The barrier is now fsync on a directory handle opened at run start, which is always delivered and gives per-run loss observation for free. |
| Round 3 and source check: no open-by-identity path exists; item capabilities are epoch-local; transparent epoch recovery is over-engineering | Accepted. An epoch change stales every open handle and the product restarts affected runs. |
| Round 3: a delayed reply to the holder's own mutation can install stale cache state after a recall; deleting the source-publication gate wholesale is unsafe | Accepted as F12. Only the two mount-wide predicates are deleted; the per-identity keyed drain stays. |
| Round 3: O_SYNC semantics vanish under write-back; copy_file_range, fallocate, and a peer's fsync bypass the break | Accepted. O_SYNC waits for durability; every data-consuming operation breaks for read and every data-mutating one recalls. |
| Round 3: a read-only Mac mount caches negative lookups it cannot revoke | Accepted. Every attached Mac mount excludes other writers. |
| Round 3: cumulative stream acks are only safe if an ack means proven withdrawal through kernel publication, in one subscription incarnation | Accepted as the definition of an ack. |
| Round 3 and source check: quota reservation has no usage source (no quotactl); immutable listing snapshots exceed readdir's promise; a loss counter has no daemon surface reachable from sandboxes | Accepted. Reservation removed in favour of delayed ENOSPC; snapshots replaced by cookie continuation; the counter is observed through the directory-handle barrier, which needs no new surface. |
| Round 3: CREATE piggyback needs the delegation reserved before the binding is exposed | Accepted, and the piggyback cuts the per-file cost to one round trip. |
| Source check: change delivery today is one slot per holder with two phases per event; the client reserves one CONTROL slot | Accepted. The Authority change is an ordered stream with cumulative acks, not a queue behind the existing two-phase path. |

## Build order

  - **Baseline.** Measure the three workloads on the current build: 40,000-file install with one and eight workers, cold and warm `git status` over 20,000 files, and a peer listing while the owner writes. Record runner-to-Authority round trip. There is no committed benchmark today.

  - **Remove the mount-wide gate.** Key the client gate on the same identity and (parent, name) coordinates the sequencer uses, or delete it and let the Authority order. This is independent of everything else and unblocks parallel creates immediately.

  - **Subscription and change entries.** Replace the N, A, and E lease families with the subscription; cache listings with attributes. Delete their tickers. This removes the readdir `ESTALE` and the lease-timing `mmap` behaviour.

  - **File write delegation.** Reserve-withdraw-grant inside CREATE and OPEN, daemon buffer with overlay, four states, flush triggers, `O_SYNC`, F4 rename-flush, break on every data-consuming operation, recall on every data-mutating one, write-through downgrade while a peer holds a cacheable handle, stale-generation rejection. Delete the D family and unconditional write-through.

  - **Loss sequence, directory-handle barrier, stale-all-handles on epoch change, re-attach.** Delete the watchdog abort and coherence-caused revokes. The F10 kernel test and a test that `FUSE_FSYNCDIR` reaches the daemon on the pinned runner kernel ship with this step and gate it.

  - **OpenSteer completion contract.** The directory-handle barrier at run start and end, restart of runs staled by an epoch change, and a pinned runner kernel.

  - **Measure again, then decide** between Authority placement and the directory-delegation extension.

Sources read: `vcs/internal/volumeserver/leases.go`, `visibility.go`, `mutation_sequencer.go`, `session.go`; `vcs/internal/authorityrpc/volume_handler_linux.go`, `protocol.go`, `client.go`; `vcs/internal/fusev3/source_publication_linux.go`, `leases_linux.go`, `coherence_linux.go`, `raw_linux.go`, `fuse_linux.go`; `vcs/internal/xfsstore/volume_linux.go` (`stableIdentityFD`), `fsync_group.go`; `vcs/internal/portablefsd/publicationgate.go`, `repairactuate_darwin.go`, `v3dataplane.go`; `proto/authority/v1/authority.proto`. Codex jobs `01a0aae4-4ed0-71d1-8934-26fb947e14b8`, `01a0ab09-a293-7662-9bb3-b0ee0522acf4`, and `01a0ab16-2e57-7740-a3db-89cd55ac6422`.
